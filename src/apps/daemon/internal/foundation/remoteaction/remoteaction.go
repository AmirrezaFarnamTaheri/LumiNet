// Package remoteaction owns retry safety for outbound HTTP mutations.
//
// It deliberately separates transport retry policy from provider-specific
// reconciliation. A mutation may be replayed automatically only when it is
// intrinsically idempotent or when its owner can prove the desired state via
// a read-only reconciliation callback after an ambiguous attempt.
package remoteaction

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SafetyClass describes when a remote mutation may be replayed.
type SafetyClass string

const (
	// Idempotent permits retry because repeating the same request preserves the
	// requested final state (for example PUT of a named resource).
	Idempotent SafetyClass = "idempotent"
	// ReconcileBeforeRetry permits retry only after a read-only reconciliation
	// proves that the previous ambiguous attempt did not already reach the
	// desired state.
	ReconcileBeforeRetry SafetyClass = "reconcile-before-retry"
	// SingleAttempt forbids automatic replay because duplicate side effects
	// cannot be excluded or reconciled safely.
	SingleAttempt SafetyClass = "single-attempt"
)

const (
	defaultMaxAttempts   = 3
	maxAutomaticAttempts = 8
	defaultBaseDelay     = 250 * time.Millisecond
	defaultMaxDelay      = 4 * time.Second
	defaultRetryAfterCap = 30 * time.Second
	retryDrainBytes      = 4 << 10
	defaultCooldownKeys  = 256
	defaultMaxInFlight   = 4
	maxScopeInFlight     = 16
)

var ErrCoordinatorCapacity = errors.New("remote action coordinator scope capacity exhausted")

// Policy is the complete retry contract for one named remote action.
type Policy struct {
	Action         string
	Class          SafetyClass
	RateLimitScope string
	MaxInFlight    int
	MaxAttempts    int
	BaseDelay      time.Duration
	MaxDelay       time.Duration
	RetryAfterCap  time.Duration
}

// DefaultPolicy returns conservative bounded defaults for an action.
func DefaultPolicy(action string, class SafetyClass) Policy {
	attempts := defaultMaxAttempts
	if class == SingleAttempt {
		attempts = 1
	}
	return Policy{
		Action:         action,
		Class:          class,
		RateLimitScope: action,
		MaxInFlight:    defaultMaxInFlight,
		MaxAttempts:    attempts,
		BaseDelay:      defaultBaseDelay,
		MaxDelay:       defaultMaxDelay,
		RetryAfterCap:  defaultRetryAfterCap,
	}
}

// RequestFactory must construct a fresh request, including a fresh body, for
// every attempt. The attempt number is one-based.
type RequestFactory func(ctx context.Context, attempt int) (*http.Request, error)

// ReconcileFunc performs a read-only check after an ambiguous mutation.
// reached=true means the desired state is already present and no replay is
// needed. reached=false means replay is allowed. An error leaves authority
// uncertain and therefore fails closed without replay.
type ReconcileFunc func(ctx context.Context) (reached bool, err error)

// Outcome reports how the action completed. Response is owned by the caller
// and must be closed. A reconciled success has Reconciled=true and Response=nil.
type Outcome struct {
	Response   *http.Response
	Attempts   int
	Reconciled bool
}

// Executor coordinates retryable mutations across calls. The original retry
// loop already bounded replay inside one call; Executor adds the missing
// second-order behavior for concurrent/periodic callers: provider-directed
// cooldown is remembered per bounded provider scope so one 429/Retry-After
// response can suppress a local retry storm across related actions without
// blocking unrelated providers. The same scope also owns a hard in-flight gate.
//
// Scope keys are canonical non-URL identifiers, never raw URLs, so credentials
// and query strings do not enter coordinator state. State is memory bounded and
// expiry based.
type Executor struct {
	mu          sync.Mutex
	cooldowns   map[string]cooldownEntry
	active      map[string]int
	changed     chan struct{}
	maxCooldown int
	sequence    uint64
	now         func() time.Time
	waitFn      func(context.Context, time.Duration) error
	jitterFn    func(time.Duration) time.Duration

	cooldownWaits atomic.Uint64
	inFlightWaits atomic.Uint64
	capacityStops atomic.Uint64
	rateLimits    atomic.Uint64
	retrySleeps   atomic.Uint64
	reconciled    atomic.Uint64
}

type cooldownEntry struct {
	until   time.Time
	touched uint64
}

// ExecutorStats exposes only aggregate coordinator state. No URL, request,
// response body, or credential-bearing value is retained.
type ExecutorStats struct {
	CooldownKeys  int    `json:"cooldown_keys"`
	ActiveScopes  int    `json:"active_scopes"`
	InFlight      int    `json:"in_flight"`
	CooldownWaits uint64 `json:"cooldown_waits"`
	InFlightWaits uint64 `json:"in_flight_waits"`
	CapacityStops uint64 `json:"capacity_stops"`
	RateLimits    uint64 `json:"rate_limits"`
	RetrySleeps   uint64 `json:"retry_sleeps"`
	Reconciled    uint64 `json:"reconciled"`
}

// NewExecutor creates an automatic mutation executor with bounded cooldown
// state. Non-positive maxCooldownKeys selects the conservative default.
func NewExecutor(maxCooldownKeys int) *Executor {
	if maxCooldownKeys <= 0 {
		maxCooldownKeys = defaultCooldownKeys
	}
	return &Executor{
		cooldowns:   make(map[string]cooldownEntry),
		active:      make(map[string]int),
		changed:     make(chan struct{}),
		maxCooldown: maxCooldownKeys,
		now:         time.Now,
		waitFn:      wait,
		jitterFn:    equalJitter,
	}
}

var defaultExecutor = NewExecutor(defaultCooldownKeys)

// DefaultExecutorStats returns aggregate retry-coordinator statistics for the
// package-level executor used by Do.
func DefaultExecutorStats() ExecutorStats { return defaultExecutor.Stats() }

// Do executes one mutation under its declared safety contract.
func Do(ctx context.Context, client *http.Client, policy Policy, makeRequest RequestFactory, reconcile ReconcileFunc) (Outcome, error) {
	return defaultExecutor.Do(ctx, client, policy, makeRequest, reconcile)
}

// Do executes one mutation under its declared safety contract while sharing
// provider cooldown and in-flight capacity with other calls using this Executor.
func (e *Executor) Do(ctx context.Context, client *http.Client, policy Policy, makeRequest RequestFactory, reconcile ReconcileFunc) (Outcome, error) {
	if ctx == nil {
		return Outcome{}, errors.New("remote action context is required")
	}
	if e == nil {
		return Outcome{}, errors.New("remote action executor is required")
	}
	if client == nil {
		return Outcome{}, errors.New("remote action HTTP client is required")
	}
	if makeRequest == nil {
		return Outcome{}, errors.New("remote action request factory is required")
	}
	policy, err := normalizePolicy(policy)
	if err != nil {
		return Outcome{}, err
	}
	if policy.Class == ReconcileBeforeRetry && reconcile == nil {
		return Outcome{}, fmt.Errorf("remote action %q requires reconciliation before retry", policy.Action)
	}

	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return Outcome{Attempts: attempt - 1}, err
		}
		release, err := e.waitForCooldownAndAcquire(ctx, policy.RateLimitScope, policy.MaxInFlight)
		if err != nil {
			return Outcome{Attempts: attempt - 1}, err
		}

		req, err := makeRequest(ctx, attempt)
		if err != nil {
			release()
			return Outcome{Attempts: attempt - 1}, fmt.Errorf("remote action %q build attempt %d: %w", policy.Action, attempt, err)
		}
		if req == nil {
			release()
			return Outcome{Attempts: attempt - 1}, fmt.Errorf("remote action %q build attempt %d returned nil request", policy.Action, attempt)
		}
		// Cancellation belongs to this authority plane, not to caller discipline.
		// Rebind even a buggy factory's background-context request so service
		// shutdown and operation cancellation always reach the in-flight I/O.
		req = req.WithContext(ctx)

		resp, requestErr := client.Do(req)
		if requestErr == nil && !retryableStatus(resp.StatusCode) {
			release()
			return Outcome{Response: resp, Attempts: attempt}, nil
		}

		lastErr = requestErr
		if requestErr == nil {
			lastErr = fmt.Errorf("retryable HTTP status %d", resp.StatusCode)
		}

		// Calculate the provider/local delay before the replay decision. Even a
		// SingleAttempt action must remember a provider rate limit for the next
		// independent call; remembering a cooldown is not replaying a side effect.
		delay := e.jitterFn(backoffDelay(policy, attempt))
		providerDelay := false
		if resp != nil {
			if retryAfter, ok := parseRetryAfter(resp.Header.Get("Retry-After"), e.now(), policy.RetryAfterCap); ok {
				delay = retryAfter
				providerDelay = true
			}
			if resp.StatusCode == http.StatusTooManyRequests {
				providerDelay = true
				e.rateLimits.Add(1)
			}
		}
		if providerDelay && delay > 0 {
			e.rememberCooldown(policy.RateLimitScope, e.now().Add(delay))
		}
		release()

		if policy.Class == SingleAttempt || attempt == policy.MaxAttempts {
			if requestErr != nil {
				closeForRetry(resp)
				return Outcome{Attempts: attempt}, fmt.Errorf("remote action %q attempt %d: %w", policy.Action, attempt, requestErr)
			}
			return Outcome{Response: resp, Attempts: attempt}, nil
		}

		if policy.Class == ReconcileBeforeRetry {
			// A retryable HTTP response still owns its transport connection until
			// the body is closed. Release it before read-only reconciliation so a
			// client with a one-connection-per-host pool cannot deadlock itself.
			closeForRetry(resp)
			resp = nil
			reached, reconcileErr := reconcile(ctx)
			if reconcileErr != nil {
				return Outcome{Attempts: attempt}, fmt.Errorf("remote action %q state uncertain after attempt %d (%v); reconciliation failed: %w", policy.Action, attempt, lastErr, reconcileErr)
			}
			if reached {
				e.reconciled.Add(1)
				return Outcome{Attempts: attempt, Reconciled: true}, nil
			}
		}

		closeForRetry(resp)
		e.retrySleeps.Add(1)
		if err := e.waitFn(ctx, delay); err != nil {
			return Outcome{Attempts: attempt}, err
		}
	}

	return Outcome{Attempts: policy.MaxAttempts}, fmt.Errorf("remote action %q exhausted retries: %w", policy.Action, lastErr)
}

// Stats returns a race-free snapshot of bounded retry coordination state.
func (e *Executor) Stats() ExecutorStats {
	if e == nil {
		return ExecutorStats{}
	}
	e.mu.Lock()
	e.pruneExpiredLocked(e.now())
	keys := len(e.cooldowns)
	activeScopes := len(e.active)
	inFlight := 0
	for _, count := range e.active {
		inFlight += count
	}
	e.mu.Unlock()
	return ExecutorStats{
		CooldownKeys:  keys,
		ActiveScopes:  activeScopes,
		InFlight:      inFlight,
		CooldownWaits: e.cooldownWaits.Load(),
		InFlightWaits: e.inFlightWaits.Load(),
		CapacityStops: e.capacityStops.Load(),
		RateLimits:    e.rateLimits.Load(),
		RetrySleeps:   e.retrySleeps.Load(),
		Reconciled:    e.reconciled.Load(),
	}
}

func (e *Executor) waitForCooldownAndAcquire(ctx context.Context, key string, maxInFlight int) (func(), error) {
	for {
		now := e.now()
		e.mu.Lock()
		e.pruneExpiredLocked(now)
		entry, ok := e.cooldowns[key]
		delay := time.Duration(0)
		if ok {
			delay = entry.until.Sub(now)
		}
		if delay <= 0 {
			if _, exists := e.active[key]; !exists && len(e.active) >= e.maxCooldown {
				e.capacityStops.Add(1)
				e.mu.Unlock()
				return nil, ErrCoordinatorCapacity
			}
			if e.active[key] < maxInFlight {
				e.active[key]++
				e.mu.Unlock()
				var once sync.Once
				return func() {
					once.Do(func() { e.releaseScope(key) })
				}, nil
			}
			changed := e.changed
			e.mu.Unlock()
			e.inFlightWaits.Add(1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		e.mu.Unlock()
		e.cooldownWaits.Add(1)
		if err := e.waitFn(ctx, delay); err != nil {
			return nil, err
		}
		// Re-check after waking because a concurrent response may have extended
		// the same provider scope's cooldown while this caller was asleep.
	}
}

func (e *Executor) releaseScope(key string) {
	e.mu.Lock()
	if e.active[key] > 1 {
		e.active[key]--
	} else {
		delete(e.active, key)
	}
	e.signalLocked()
	e.mu.Unlock()
}

func (e *Executor) signalLocked() {
	close(e.changed)
	e.changed = make(chan struct{})
}

func (e *Executor) rememberCooldown(key string, until time.Time) {
	if key == "" || until.IsZero() {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	e.pruneExpiredLocked(now)
	e.sequence++
	if current, ok := e.cooldowns[key]; ok {
		if current.until.After(until) {
			until = current.until
		}
		e.cooldowns[key] = cooldownEntry{until: until, touched: e.sequence}
		e.signalLocked()
		return
	}
	if len(e.cooldowns) >= e.maxCooldown {
		// Evict the least-recently-touched key. This is deliberately O(N) over a
		// small hard cap instead of adding a second unbounded bookkeeping index.
		var victim string
		var oldest uint64
		for candidate, state := range e.cooldowns {
			if victim == "" || state.touched < oldest {
				victim, oldest = candidate, state.touched
			}
		}
		if victim != "" {
			delete(e.cooldowns, victim)
		}
	}
	e.cooldowns[key] = cooldownEntry{until: until, touched: e.sequence}
	e.signalLocked()
}

func (e *Executor) pruneExpiredLocked(now time.Time) {
	for key, state := range e.cooldowns {
		if !state.until.After(now) {
			delete(e.cooldowns, key)
		}
	}
}

func normalizePolicy(policy Policy) (Policy, error) {
	policy.Action = strings.TrimSpace(policy.Action)
	if policy.Action == "" {
		return Policy{}, errors.New("remote action name is required")
	}
	switch policy.Class {
	case Idempotent, ReconcileBeforeRetry, SingleAttempt:
	default:
		return Policy{}, fmt.Errorf("remote action %q has invalid safety class %q", policy.Action, policy.Class)
	}
	policy.RateLimitScope = strings.TrimSpace(policy.RateLimitScope)
	if policy.RateLimitScope == "" {
		policy.RateLimitScope = policy.Action
	}
	if len(policy.RateLimitScope) > 128 || strings.Contains(policy.RateLimitScope, "://") || strings.ContainsAny(policy.RateLimitScope, "?#\r\n\t") {
		return Policy{}, fmt.Errorf("remote action %q has invalid rate-limit scope", policy.Action)
	}
	if policy.MaxInFlight <= 0 {
		policy.MaxInFlight = defaultMaxInFlight
	}
	if policy.MaxInFlight > maxScopeInFlight {
		policy.MaxInFlight = maxScopeInFlight
	}
	if policy.MaxAttempts <= 0 {
		policy.MaxAttempts = defaultMaxAttempts
	}
	if policy.MaxAttempts > maxAutomaticAttempts {
		policy.MaxAttempts = maxAutomaticAttempts
	}
	if policy.Class == SingleAttempt {
		policy.MaxAttempts = 1
	}
	if policy.BaseDelay <= 0 {
		policy.BaseDelay = defaultBaseDelay
	}
	if policy.MaxDelay <= 0 {
		policy.MaxDelay = defaultMaxDelay
	}
	if policy.MaxDelay < policy.BaseDelay {
		policy.MaxDelay = policy.BaseDelay
	}
	if policy.RetryAfterCap <= 0 {
		policy.RetryAfterCap = defaultRetryAfterCap
	}
	return policy, nil
}

func equalJitter(delay time.Duration) time.Duration {
	if delay <= time.Nanosecond {
		return delay
	}
	half := delay / 2
	span := delay - half
	return half + time.Duration(rand.Int63n(int64(span)+1))
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func backoffDelay(policy Policy, failedAttempt int) time.Duration {
	delay := policy.BaseDelay
	for n := 1; n < failedAttempt; n++ {
		if delay >= policy.MaxDelay/2 {
			return policy.MaxDelay
		}
		delay *= 2
	}
	if delay > policy.MaxDelay {
		return policy.MaxDelay
	}
	return delay
}

func parseRetryAfter(value string, now time.Time, capDelay time.Duration) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return 0, false
		}
		// Retry-After is provider-controlled. Saturate before converting seconds
		// to time.Duration so an enormous integer cannot overflow into a
		// negative/immediate retry.
		if capDelay > 0 && seconds > int64(capDelay/time.Second) {
			return capDelay, true
		}
		const maxDurationSeconds = int64((1<<63 - 1) / int64(time.Second))
		if seconds > maxDurationSeconds {
			return clampDelay(time.Duration(1<<63-1), capDelay), true
		}
		return clampDelay(time.Duration(seconds)*time.Second, capDelay), true
	} else if numErr, ok := err.(*strconv.NumError); ok && errors.Is(numErr.Err, strconv.ErrRange) && !strings.HasPrefix(value, "-") {
		// A positive decimal integer larger than int64 is semantically an
		// extremely long server delay. Treat it as saturated rather than as an
		// invalid header that would fall back to a short local backoff.
		if capDelay > 0 {
			return capDelay, true
		}
		return time.Duration(1<<63 - 1), true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := when.Sub(now)
	if delay < 0 {
		delay = 0
	}
	return clampDelay(delay, capDelay), true
}

func clampDelay(delay, capDelay time.Duration) time.Duration {
	if capDelay > 0 && delay > capDelay {
		return capDelay
	}
	return delay
}

func closeForRetry(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, resp.Body, retryDrainBytes)
	_ = resp.Body.Close()
}

func wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
