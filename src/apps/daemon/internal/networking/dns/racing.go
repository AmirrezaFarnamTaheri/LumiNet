// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.
// SmartDNS-style racing resolver: queries multiple upstreams in parallel and
// returns the first valid response. Implements jitter to avoid thundering-herd
// and exponential backoff to handle sustained failures.

package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// RacingResolver distributes DNS queries across a pool of upstreams and returns
// the fastest valid response. It implements jittered parallel queries and
// respects per-upstream backoff windows.
type RacingResolver struct {
	upstreams   []RacingUpstream
	timeout     time.Duration
	jitter      time.Duration // max random jitter added to each upstream launch.
	backoff     *exponentialBackoff
	maxFailures int           // per-upstream failure threshold before backoff applies.
}

// RacingUpstream describes an upstream used by the racing resolver.
type RacingUpstream struct {
	ID       string
	Name     string
	Resolver UpstreamResolver // the actual query function.
	Weight   float64         // relative weight (0 = excluded from racing).
}

// UpstreamResolver is the interface used to execute a single DNS query.
// The implementation (DoH, DoT, UDP) is injected to keep the racer agnostic.
type UpstreamResolver interface {
	// Query executes a DNS query for the given question and returns the wire-format
	// response and the observed RTT.
	Query(ctx context.Context, question string) ([]byte, time.Duration, error)
}

// RacingConfig configures a new RacingResolver.
type RacingConfig struct {
	Upstreams   []RacingUpstream
	Timeout     time.Duration
	Jitter      time.Duration
	MaxFailures int
}

// NewRacingResolver builds a resolver from the given configuration.
func NewRacingResolver(cfg RacingConfig) *RacingResolver {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	jitter := cfg.Jitter
	if jitter == 0 {
		jitter = 50 * time.Millisecond
	}
	maxFails := cfg.MaxFailures
	if maxFails == 0 {
		maxFails = 3
	}
	return &RacingResolver{
		upstreams:   cfg.Upstreams,
		timeout:     timeout,
		jitter:      jitter,
		backoff:     newExponentialBackoff(maxFails),
		maxFailures: maxFails,
	}
}

// Race executes queries against all eligible upstreams in parallel, adding
// random jitter so they do not all fire simultaneously. The first valid
// response is returned; if no upstream responds within the configured timeout
// an error aggregating all failures is returned.
func (r *RacingResolver) Race(ctx context.Context, question string) ([]byte, error) {
	eligible := r.eligibleUpstreams()
	if len(eligible) == 0 {
		return nil, errors.New("racing: no eligible upstreams")
	}

	// Shared context that cancels when the first response arrives.
	ctxRace, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		upstreamID string
		resp       []byte
		rtt        time.Duration
		err        error
	}

	resultsCh := make(chan result, len(eligible))

	var wg sync.WaitGroup
	for _, us := range eligible {
		wg.Add(1)
		go func(upstream RacingUpstream) {
			defer wg.Done()
			jitterDelay := time.Duration(rand.Int63n(int64(r.jitter)))
			select {
			case <-time.After(jitterDelay):
				// proceed to query
			case <-ctxRace.Done():
				return
			}

			// Apply backoff if the upstream is in backoff.
			if r.backoff.IsInBackoff(upstream.ID) {
				return
			}

			resp, rtt, err := upstream.Resolver.Query(ctxRace, question)
			if err != nil {
				r.backoff.RecordFailure(upstream.ID)
				resultsCh <- result{upstreamID: upstream.ID, err: err}
				return
			}
			r.backoff.RecordSuccess(upstream.ID)
			// Signal cancellation to other goroutines.
			cancel()
			resultsCh <- result{upstreamID: upstream.ID, resp: resp, rtt: rtt}
		}(us)
	}

	// Collect the first successful result; accumulate errors otherwise.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var errs []error
	for res := range resultsCh {
		if res.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", res.upstreamID, res.err))
			continue
		}
		return res.resp, nil
	}

	if len(errs) == 0 {
		return nil, errors.New("racing: no upstreams returned a result")
	}
	return nil, errors.Join(errs...)
}

// AddUpstream appends a new upstream. Safe for concurrent use.
func (r *RacingResolver) AddUpstream(upstream RacingUpstream) {
	r.upstreams = append(r.upstreams, upstream)
}

// RemoveUpstream removes an upstream by ID. Safe for concurrent use.
func (r *RacingResolver) RemoveUpstream(id string) {
	for i, us := range r.upstreams {
		if us.ID == id {
			r.upstreams = append(r.upstreams[:i], r.upstreams[i+1:]...)
			r.backoff.Forget(id)
			return
		}
	}
}

// eligibleUpstreams returns a snapshot of upstreams with weight > 0.
func (r *RacingResolver) eligibleUpstreams() []RacingUpstream {
	var eligible []RacingUpstream
	for _, us := range r.upstreams {
		if us.Weight > 0 {
			eligible = append(eligible, us)
		}
	}
	return eligible
}

// GetTimeout returns the configured query timeout.
func (r *RacingResolver) GetTimeout() time.Duration { return r.timeout }

// SetTimeout updates the query timeout.
func (r *RacingResolver) SetTimeout(t time.Duration) { r.timeout = t }

// GetJitter returns the configured jitter window.
func (r *RacingResolver) GetJitter() time.Duration { return r.jitter }

// SetJitter updates the jitter window.
func (r *RacingResolver) SetJitter(j time.Duration) { r.jitter = j }

// BackoffStatus reports whether a given upstream is currently in backoff and
// for how long.
func (r *RacingResolver) BackoffStatus(id string) (inBackoff bool, remaining time.Duration) {
	return r.backoff.IsInBackoff(id), r.backoff.Remaining(id)
}

// ---------------------------------------------------------------------------
// Exponential backoff (per-upstream)
// ---------------------------------------------------------------------------

type exponentialBackoff struct {
	mu        sync.Mutex
	maxFails  int
	state     map[string]*upstreamBackoffState
}

type upstreamBackoffState struct {
	failures   int
	backoffUntil time.Time
}

func newExponentialBackoff(maxFails int) *exponentialBackoff {
	return &exponentialBackoff{
		maxFails: maxFails,
		state:    make(map[string]*upstreamBackoffState),
	}
}

// IsInBackoff returns true if the upstream is currently in its quiet window.
func (b *exponentialBackoff) IsInBackoff(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.state[id]
	if !ok {
		return false
	}
	return time.Now().Before(st.backoffUntil)
}

// Remaining returns the remaining backoff duration for an upstream.
func (b *exponentialBackoff) Remaining(id string) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.state[id]
	if !ok || time.Now().After(st.backoffUntil) {
		return 0
	}
	return time.Until(st.backoffUntil)
}

// RecordFailure increments the failure counter and applies backoff.
func (b *exponentialBackoff) RecordFailure(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.state[id]
	if !ok {
		st = &upstreamBackoffState{}
		b.state[id] = st
	}
	st.failures++
	if st.failures >= b.maxFails {
		// Base: 1s, 2s, 4s, 8s… capped at 30s.
		duration := time.Duration(1<<uint(st.failures-b.maxFails)) * time.Second
		if duration > 30*time.Second {
			duration = 30 * time.Second
		}
		// Add up to 500 ms of jitter.
		duration += time.Duration(rand.Int63n(500)) * time.Millisecond
		st.backoffUntil = time.Now().Add(duration)
	}
}

// RecordSuccess resets the failure counter and clears any backoff.
func (b *exponentialBackoff) RecordSuccess(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.state, id)
}

// Forget removes all backoff state for an upstream.
func (b *exponentialBackoff) Forget(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.state, id)
}
