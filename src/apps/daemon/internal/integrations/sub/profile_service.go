package sub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/maybeknott/luminet/internal/foundation/redact"
	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

// ProfileInfo carries provider-reported subscription metadata. It is advisory:
// providers differ widely in what they report and values can be stale.
type ProfileInfo struct {
	Upload       int64     `json:"upload,omitempty"`
	Download     int64     `json:"download,omitempty"`
	Total        int64     `json:"total,omitempty"`
	Expire       time.Time `json:"expire,omitempty"`
	RefillDate   time.Time `json:"refill_date,omitempty"`
	Announcement string    `json:"announcement,omitempty"`
}

// SourceHealth tracks per-source failure/success evidence for backoff gating.
type SourceHealth struct {
	LastAttemptAt       time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt       time.Time `json:"last_success_at,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	NextEligibleAt      time.Time `json:"next_eligible_at,omitempty"`
	LastError           string    `json:"last_error,omitempty"`
	FailureKind         string    `json:"failure_kind,omitempty"`
}

// SourceValidator carries conditional-GET validators (ETag / Last-Modified).
type SourceValidator struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// ManagedProfile is the daemon-owned subscription profile record. Nodes hold
// parsed proxy configs; they are deliberately excluded from JSON so provider
// credentials never reach API responses or logs.
type ManagedProfile struct {
	ID                    string                             `json:"id"`
	Name                  string                             `json:"name"`
	URL                   string                             `json:"url"`
	Mirrors               []string                           `json:"mirrors,omitempty"`
	Active                bool                               `json:"active"`
	AutoRefresh           bool                               `json:"auto_refresh"`
	RemoteFetchEnabled    bool                               `json:"remote_fetch_enabled"`
	UpdateIntervalH       int                                `json:"update_interval_hours"`
	LastUpdated           time.Time                          `json:"last_updated,omitempty"`
	NodeCount             int                                `json:"node_count"`
	Info                  *ProfileInfo                       `json:"info,omitempty"`
	Nodes                 []*proxyconfig.ProxyConfig         `json:"-"`
	RefreshQueued         bool                               `json:"refresh_queued,omitempty"`
	LastSourceURL         string                             `json:"last_source_url,omitempty"`
	SourceHealth          SourceHealth                       `json:"source_health"`
	SourceHealthByURL     map[string]SourceHealth            `json:"source_health_by_url,omitempty"`
	SourceValidatorsByURL map[string]SourceValidator         `json:"source_validators_by_url,omitempty"`
}

// ProfilePatch is a partial update; nil fields leave the stored value intact.
type ProfilePatch struct {
	Name               *string   `json:"name,omitempty"`
	URL                *string   `json:"url,omitempty"`
	Mirrors            *[]string `json:"mirrors,omitempty"`
	UpdateIntervalH    *int      `json:"update_interval_hours,omitempty"`
	Active             *bool     `json:"active,omitempty"`
	AutoRefresh        *bool     `json:"auto_refresh,omitempty"`
	RemoteFetchEnabled *bool     `json:"remote_fetch_enabled,omitempty"`
}

// ProfileRefresh is a validated refresh result awaiting atomic application.
type ProfileRefresh struct {
	Name        string
	LastUpdated time.Time
	Info        *ProfileInfo
	NodeCount   int
	Nodes       []*proxyconfig.ProxyConfig
}

const (
	profileSourceBackoffBase   = 30 * time.Second
	profileSourceRetryAfterCap = 24 * time.Hour
	maxProfileMirrors          = 3
	maxProfileSourceURLLen     = 2048
	maxSourceErrorLen          = 512
)

var (
	ErrProfileNotFound = errors.New("profile not found")
)

// ProfileFetcher is the bounded remote-fetch seam used for subscription
// sources. *Egress is the production implementation.
type ProfileFetcher interface {
	Fetch(ctx context.Context, url string) (EgressResponse, error)
}

type conditionalFetchClient interface {
	FetchConditional(ctx context.Context, url, etag string) (EgressResponse, error)
}

// profileRefreshTask owns one in-flight queued refresh generation so that
// replacement, deletion, URL changes, owner teardown, and Close can cancel it.
type profileRefreshTask struct {
	gen    uint64
	cancel context.CancelFunc
}

// ProfileService owns subscription profile lifecycle: CRUD, multi-source
// refresh with per-source health tracking and backoff, node resolution via the
// materialized-node catalogue, and daemon-owned refresh task lifetime.
//
// Concurrency: mu guards profiles and the task table; refreshMu serialises the
// auto-refresh loop lifecycle; refreshWG tracks in-flight workers for Close.
type ProfileService struct {
	mu        sync.RWMutex
	profiles  map[string]ManagedProfile
	egress    ProfileFetcher
	baseCtx   context.Context
	tasks     map[string]*profileRefreshTask
	nextGen   uint64
	catalogue *NodeCatalogue

	refreshMu sync.Mutex
	autoStop  chan struct{}
	refreshWG sync.WaitGroup
}

// NewProfileServiceWithContext builds a service whose queued refreshes inherit
// ctx: cancelling the owner cancels every in-flight refresh it spawned.
func NewProfileServiceWithContext(ctx context.Context, fetcher ProfileFetcher) *ProfileService {
	if ctx == nil {
		ctx = context.Background()
	}
	service := &ProfileService{
		profiles: make(map[string]ManagedProfile),
		egress:   fetcher,
		baseCtx:  ctx,
		tasks:    make(map[string]*profileRefreshTask),
	}
	if catalogue, err := NewNodeCatalogue(); err == nil {
		service.catalogue = catalogue
	}
	return service
}

// newProfileService is the test-facing alias kept for existing call sites.
func newProfileService(ctx context.Context, fetcher ProfileFetcher) *ProfileService {
	return NewProfileServiceWithContext(ctx, fetcher)
}

// NewProfileService builds a service with remote fetching disabled until an
// enabled egress boundary is supplied elsewhere.
func NewProfileService() *ProfileService {
	return NewProfileServiceWithContext(context.Background(), &Egress{})
}

// --- CRUD ---

func (s *ProfileService) Get(id string) (ManagedProfile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	profile, ok := s.profiles[id]
	return cloneManagedProfile(profile), ok
}

func (s *ProfileService) List() []ManagedProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ManagedProfile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		out = append(out, cloneManagedProfile(profile))
	}
	return out
}

func (s *ProfileService) Create(profile ManagedProfile) ManagedProfile {
	stored := cloneManagedProfile(profile)
	if stored.ID == "" {
		stored.ID = newProfileID()
	}
	stored.Mirrors = normalizeProfileMirrors(stored.URL, stored.Mirrors)
	stored.SourceHealthByURL = pruneSourceHealth(stored.URL, stored.Mirrors, stored.SourceHealthByURL)
	stored.SourceValidatorsByURL = pruneSourceValidators(stored.URL, stored.Mirrors, stored.SourceValidatorsByURL)

	s.mu.Lock()
	s.profiles[stored.ID] = stored
	snapshot := cloneManagedProfile(stored)
	s.mu.Unlock()
	return snapshot
}

func (s *ProfileService) Update(id string, patch ProfilePatch) (ManagedProfile, bool) {
	s.mu.Lock()
	profile, ok := s.profiles[id]
	if !ok {
		s.mu.Unlock()
		return ManagedProfile{}, false
	}
	urlChanged := patch.URL != nil && *patch.URL != profile.URL
	applyPatch(&profile, &patch)
	if patch.Mirrors != nil || urlChanged {
		profile.Mirrors = normalizeProfileMirrors(profile.URL, profile.Mirrors)
	}
	if urlChanged {
		profile.LastUpdated = time.Time{}
		profile.Info = nil
		profile.NodeCount = 0
		profile.Nodes = nil
		profile.SourceHealth = SourceHealth{}
		profile.SourceHealthByURL = nil
		profile.SourceValidatorsByURL = nil
		profile.LastSourceURL = ""
		cancelTask := s.cancelTaskLocked(id)
		defer cancelTask()
		if s.catalogue != nil {
			s.catalogue.Clear(id)
		}
	} else if profile.LastSourceURL != "" && !profileContainsSource(profile, profile.LastSourceURL) {
		// A removed mirror must not stay pinned as the last-good source.
		profile.LastSourceURL = ""
	}
	if err := validateProfileURLs(profile); err != nil {
		s.mu.Unlock()
		return ManagedProfile{}, false
	}
	s.profiles[id] = profile
	snapshot := cloneManagedProfile(profile)
	s.mu.Unlock()
	return snapshot, true
}

func (s *ProfileService) Delete(id string) bool {
	s.mu.Lock()
	if _, ok := s.profiles[id]; !ok {
		s.mu.Unlock()
		return false
	}
	delete(s.profiles, id)
	cancelTask := s.cancelTaskLocked(id)
	s.mu.Unlock()

	if s.catalogue != nil {
		s.catalogue.Clear(id)
	}
	cancelTask()
	return true
}

// --- Node resolution (delegates to the materialized-node catalogue) ---

func (s *ProfileService) ListNodes(profileID string, includeHidden bool) ([]MaterializedNodeView, bool) {
	s.mu.RLock()
	_, ok := s.profiles[profileID]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if s.catalogue == nil {
		return []MaterializedNodeView{}, true
	}
	return s.catalogue.List(profileID, includeHidden), true
}

func (s *ProfileService) SetNodesHidden(profileID string, ids []string, hidden bool) error {
	if s.catalogue == nil {
		return fmt.Errorf("subscription nodes are unavailable for profile %q", profileID)
	}
	return s.catalogue.SetHidden(profileID, ids, hidden)
}

func (s *ProfileService) ResolveNode(profileID, nodeID string) (*proxyconfig.ProxyConfig, error) {
	if s.catalogue == nil {
		return nil, fmt.Errorf("subscription nodes are unavailable for profile %q", profileID)
	}
	return s.catalogue.Resolve(profileID, nodeID)
}

// --- Refresh ---

// Refresh fetches the profile's eligible sources in preference order (last
// good source first), applying the first success. Explicit refreshes ignore
// scheduling backoff: when every source is gated they are still attempted in
// declared order so a manual refresh never dead-ends behind stale gates.
func (s *ProfileService) Refresh(ctx context.Context, id string) (ManagedProfile, error) {
	profile, ok := s.Get(id)
	if !ok {
		return ManagedProfile{}, fmt.Errorf("%w: %q", ErrProfileNotFound, id)
	}
	if !profile.RemoteFetchEnabled || s.egress == nil {
		return ManagedProfile{}, ErrRemoteFetchDisabled
	}

	now := time.Now().UTC()
	sources := orderedProfileSources(profile, now)
	if len(sources) == 0 {
		sources = profileSources(profile)
	}
	if len(sources) == 0 {
		return ManagedProfile{}, fmt.Errorf("profile %q has no configured subscription source", id)
	}

	var failures []error
	for _, sourceURL := range sources {
		validator := profile.SourceValidatorsByURL[sourceURL]
		response, err := fetchProfileSource(ctx, s.egress, sourceURL, validator)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				// Cancellation is ownership churn, never source evidence.
				return ManagedProfile{}, err
			}
			attemptedAt := time.Now().UTC()
			s.recordSourceFailure(profile.ID, profile.URL, sourceURL, err, attemptedAt)
			failures = append(failures, fmt.Errorf("source %q: %w", sourceLabel(sourceURL), err))
			continue
		}
		if response.StatusCode == http.StatusNotModified {
			if validator.ETag == "" && validator.LastModified == "" {
				err = errors.New("subscription source returned 304 without an accepted validator")
				s.recordSourceFailure(profile.ID, profile.URL, sourceURL, err, time.Now().UTC())
				failures = append(failures, fmt.Errorf("source %q: %w", sourceLabel(sourceURL), err))
				continue
			}
			updated, applied := s.applyNotModified(profile.ID, profile.URL, sourceURL, response.Header, time.Now().UTC())
			if !applied {
				return ManagedProfile{}, fmt.Errorf("profile %q changed during refresh", id)
			}
			return updated, nil
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			err = fmt.Errorf("subscription HTTP status %d", response.StatusCode)
			attemptedAt := time.Now().UTC()
			minimumDelay := time.Duration(0)
			if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
				minimumDelay = sourceRetryAfterDelay(response.Header, attemptedAt)
			}
			s.recordSourceFailureWithMinimumDelay(profile.ID, profile.URL, sourceURL, err, attemptedAt, minimumDelay)
			failures = append(failures, fmt.Errorf("source %q: %w", sourceLabel(sourceURL), err))
			continue
		}

		configs, parseErr := ParseContent(string(response.Body))
		if parseErr != nil {
			err = fmt.Errorf("validate subscription payload: %w", parseErr)
			// Payload validity is local CPU work, not a rate-limit condition:
			// record it without gating so callers can retry immediately.
			s.recordSourceFailureWithMinimumDelay(profile.ID, profile.URL, sourceURL, err, time.Now().UTC(), -1)
			failures = append(failures, fmt.Errorf("source %q: %w", sourceLabel(sourceURL), err))
			continue
		}
		info, refreshedName := profileInfoFromHeaders(response.Header)
		headerValidator := sourceValidatorFromHeaders(response.Header)
		updated, applied, applyErr := s.applyValidatedRefreshWithError(profile.ID, profile.URL, sourceURL, ProfileRefresh{
			Name:        refreshedName,
			LastUpdated: time.Now().UTC(),
			Info:        info,
			NodeCount:   len(configs),
			Nodes:       configs,
		}, &headerValidator)
		if applyErr != nil {
			s.recordSourceFailure(profile.ID, profile.URL, sourceURL, applyErr, time.Now().UTC())
			return ManagedProfile{}, applyErr
		}
		if !applied {
			return ManagedProfile{}, fmt.Errorf("profile %q changed during refresh", id)
		}
		return updated, nil
	}
	if len(failures) == 0 {
		return ManagedProfile{}, fmt.Errorf("profile %q has no eligible subscription source", id)
	}
	return ManagedProfile{}, fmt.Errorf("profile %q refresh failed across %d source(s): %w", id, len(failures), errors.Join(failures...))
}

// ApplyRefresh atomically applies fetched state when the profile still exists
// and still points at expectedURL. The URL guard prevents an older in-flight
// refresh from overwriting a profile after its source has changed.
func (s *ProfileService) ApplyRefresh(id, expectedURL string, refresh ProfileRefresh) (ManagedProfile, bool) {
	updated, applied, _ := s.applyValidatedRefreshWithError(id, expectedURL, expectedURL, refresh, nil)
	return updated, applied
}

func (s *ProfileService) applyValidatedRefreshWithError(id, expectedPrimaryURL, sourceURL string, refresh ProfileRefresh, validator *SourceValidator) (ManagedProfile, bool, error) {
	s.mu.Lock()
	profile, ok := s.profiles[id]
	if !ok || profile.URL != expectedPrimaryURL || !profileContainsSource(profile, sourceURL) {
		s.mu.Unlock()
		return ManagedProfile{}, false, fmt.Errorf("profile %q or source %q changed during refresh", id, sourceLabel(sourceURL))
	}

	if refresh.Info != nil && refresh.Info.Announcement != "" {
		infoCopy := *refresh.Info
		profile.Info = &infoCopy
	}
	if refresh.Name != "" {
		profile.Name = refresh.Name
	}
	lastUpdated := refresh.LastUpdated
	if lastUpdated.IsZero() {
		lastUpdated = time.Now().UTC()
	}
	profile.LastUpdated = lastUpdated
	if refresh.NodeCount > 0 {
		profile.NodeCount = refresh.NodeCount
	} else {
		profile.NodeCount = len(refresh.Nodes)
	}
	profile.Nodes = append([]*proxyconfig.ProxyConfig(nil), refresh.Nodes...)
	profile.LastSourceURL = sourceURL

	now := time.Now().UTC()
	health := SourceHealth{
		LastAttemptAt:  now,
		LastSuccessAt:  now,
		FailureKind:    "",
		LastError:      "",
	}
	if profile.SourceHealthByURL == nil {
		profile.SourceHealthByURL = make(map[string]SourceHealth)
	}
	profile.SourceHealthByURL[sourceURL] = health
	profile.SourceHealth = health
	if validator != nil {
		if profile.SourceValidatorsByURL == nil {
			profile.SourceValidatorsByURL = make(map[string]SourceValidator)
		}
		profile.SourceValidatorsByURL[sourceURL] = *validator
	}
	s.profiles[id] = profile
	snapshot := cloneManagedProfile(profile)
	s.mu.Unlock()

	if s.catalogue != nil && len(refresh.Nodes) > 0 {
		// Materialization is best-effort view state; profile state above stays
		// authoritative even when every node collapses to a duplicate.
		_ = s.catalogue.Replace(id, refresh.Nodes)
	}
	return snapshot, true, nil
}

// applyNotModified records a 304 as a successful attempt: freshness advances
// and validators upgrade, while accepted content (name, info, nodes) survives
// untouched unless the response supplies explicit replacements.
func (s *ProfileService) applyNotModified(profileID, primaryURL, sourceURL string, header http.Header, now time.Time) (ManagedProfile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.profiles[profileID]
	if !ok || profile.URL != primaryURL || !profileContainsSource(profile, sourceURL) {
		return ManagedProfile{}, false
	}
	if info, _ := profileInfoFromHeaders(header); info != nil {
		profile.Info = info
	}
	validator := sourceValidatorFromHeaders(header)
	if validator.ETag != "" || validator.LastModified != "" {
		if profile.SourceValidatorsByURL == nil {
			profile.SourceValidatorsByURL = make(map[string]SourceValidator)
		}
		profile.SourceValidatorsByURL[sourceURL] = validator
	}
	profile.LastUpdated = now
	profile.LastSourceURL = sourceURL
	health := SourceHealth{
		LastAttemptAt: now,
		LastSuccessAt: now,
	}
	if profile.SourceHealthByURL == nil {
		profile.SourceHealthByURL = make(map[string]SourceHealth)
	}
	profile.SourceHealthByURL[sourceURL] = health
	profile.SourceHealth = health
	s.profiles[profileID] = profile
	return cloneManagedProfile(profile), true
}

// --- Failure recording ---

// recordRefreshFailure is the compatibility shim for callers that only know
// the primary URL; failures land on the primary source's health record.
func (s *ProfileService) recordRefreshFailure(id, expectedURL string, refreshErr error, attemptedAt time.Time) {
	s.recordSourceFailure(id, expectedURL, expectedURL, refreshErr, attemptedAt)
}

func (s *ProfileService) recordSourceFailure(id, expectedPrimaryURL, sourceURL string, refreshErr error, attemptedAt time.Time) {
	s.recordSourceFailureWithMinimumDelay(id, expectedPrimaryURL, sourceURL, refreshErr, attemptedAt, 0)
}

// recordSourceFailureWithMinimumDelay bumps the per-source failure counter,
// applies exponential backoff, honors server-supplied Retry-After minimums,
// and mirrors derived evidence onto the aggregate field. A negative minimum
// delay means zero gating (payload-validity class failures).
func (s *ProfileService) recordSourceFailureWithMinimumDelay(id, expectedPrimaryURL, sourceURL string, refreshErr error, attemptedAt time.Time, minimumDelay time.Duration) {
	s.mu.Lock()
	profile, ok := s.profiles[id]
	if !ok || profile.URL != expectedPrimaryURL || !profileContainsSource(profile, sourceURL) {
		s.mu.Unlock()
		return
	}
	if profile.SourceHealthByURL == nil {
		profile.SourceHealthByURL = make(map[string]SourceHealth)
	}
	health := profile.SourceHealthByURL[sourceURL]
	health.LastAttemptAt = attemptedAt
	health.ConsecutiveFailures++
	delay := profileSourceBackoff(health.ConsecutiveFailures)
	if minimumDelay < 0 {
		delay = 0
	} else if minimumDelay > delay {
		delay = minimumDelay
	}
	if delay > 0 {
		health.NextEligibleAt = attemptedAt.Add(delay)
	} else {
		health.NextEligibleAt = time.Time{}
	}
	health.LastError = boundedSourceError(refreshErr)
	health.FailureKind = classifySourceFailure(refreshErr)
	profile.SourceHealthByURL[sourceURL] = health

	profile.SourceHealth.LastAttemptAt = attemptedAt
	profile.SourceHealth.ConsecutiveFailures++
	profile.SourceHealth.LastError = health.LastError
	profile.SourceHealth.FailureKind = health.FailureKind
	profile.SourceHealth.NextEligibleAt = earliestEligibleAt(profile, attemptedAt)
	s.profiles[id] = profile
	s.mu.Unlock()
}

// --- Refresh task queue ---

// QueueRefresh queues a manual refresh, replacing any in-flight one.
func (s *ProfileService) QueueRefresh(id string) bool {
	return s.queueRefresh(id, true, func(ManagedProfile) bool { return true })
}

// queueRefresh installs refresh ownership under the current profile state and
// spawns the worker. replace=true cancels any prior in-flight task; otherwise
// an in-flight task makes the call a no-op so schedulers never double-spawn.
func (s *ProfileService) queueRefresh(id string, replace bool, eligible func(ManagedProfile) bool) bool {
	var spawn func(context.Context, uint64)
	s.mu.Lock()
	profile, ok := s.profiles[id]
	if !ok || !eligible(cloneManagedProfile(profile)) {
		s.mu.Unlock()
		return false
	}
	if existing, inflight := s.tasks[id]; inflight {
		if !replace {
			s.mu.Unlock()
			return false
		}
		existing.cancel()
		delete(s.tasks, id)
	}
	if replace {
		profile.RefreshQueued = true
		s.profiles[id] = profile
	}
	s.nextGen++
	gen := s.nextGen
	taskCtx, cancel := context.WithCancel(s.baseCtx)
	s.tasks[id] = &profileRefreshTask{gen: gen, cancel: cancel}
	s.refreshWG.Add(1)
	spawnCtx := taskCtx
	s.mu.Unlock()

	go func() {
		defer s.refreshWG.Done()
		_, _ = s.Refresh(spawnCtx, id)
		s.finishQueuedRefresh(id, gen)
	}()
	_ = spawn
	return true
}

// finishQueuedRefresh releases ownership for exactly the generation this
// worker started; a replacement task keeps its own entry untouched.
func (s *ProfileService) finishQueuedRefresh(id string, gen uint64) {
	s.mu.Lock()
	if profile, ok := s.profiles[id]; ok {
		profile.RefreshQueued = false
		s.profiles[id] = profile
	}
	if task, ok := s.tasks[id]; ok && task.gen == gen {
		delete(s.tasks, id)
	}
	s.mu.Unlock()
}

// QueueDueRefreshes spawns workers for auto-refresh profiles whose interval
// elapsed and whose sources are outside their backoff window. In-flight
// refreshes are never duplicated.
func (s *ProfileService) QueueDueRefreshes(now time.Time) int {
	s.mu.RLock()
	due := make([]string, 0, len(s.profiles))
	for id, profile := range s.profiles {
		if profileRefreshDue(profile, now) {
			due = append(due, id)
		}
	}
	s.mu.RUnlock()

	queued := 0
	for _, id := range due {
		if s.queueRefresh(id, false, func(current ManagedProfile) bool {
			return profileRefreshDue(current, now)
		}) {
			queued++
		}
	}
	return queued
}

// StartAutoRefresh launches the periodic scheduler loop; it reports whether a
// loop was started (false when the interval is invalid or one already runs).
func (s *ProfileService) StartAutoRefresh(pollInterval time.Duration) bool {
	if pollInterval <= 0 {
		return false
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if s.autoStop != nil {
		return false
	}
	stop := make(chan struct{})
	s.autoStop = stop
	s.refreshWG.Add(1)
	go func() {
		defer s.refreshWG.Done()
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-s.baseCtx.Done():
				return
			case <-ticker.C:
				s.QueueDueRefreshes(time.Now().UTC())
			}
		}
	}()
	return true
}

// Close stops the scheduler, cancels every in-flight refresh, and waits for
// the workers to drain or the context to expire.
func (s *ProfileService) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.refreshMu.Lock()
	if s.autoStop != nil {
		close(s.autoStop)
		s.autoStop = nil
	}
	s.refreshMu.Unlock()

	s.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(s.tasks))
	for _, task := range s.tasks {
		cancels = append(cancels, task.cancel)
	}
	s.tasks = make(map[string]*profileRefreshTask)
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}

	done := make(chan struct{})
	go func() {
		s.refreshWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// cancelTaskLocked cancels and removes the profile's in-flight task, if any.
// Callers must invoke the returned func after releasing s.mu.
func (s *ProfileService) cancelTaskLocked(id string) context.CancelFunc {
	if task, ok := s.tasks[id]; ok {
		delete(s.tasks, id)
		return task.cancel
	}
	return func() {}
}

// --- Internal helpers ---

func newProfileID() string {
	return fmt.Sprintf("profile-%d", time.Now().UnixNano())
}

// cloneManagedProfile returns an independent snapshot: mutable maps, slices,
// and the Info pointer are copied so callers can never mutate stored state.
// Proxy configs themselves are treated as immutable once parsed.
func cloneManagedProfile(profile ManagedProfile) ManagedProfile {
	clone := profile
	if profile.Info != nil {
		infoCopy := *profile.Info
		clone.Info = &infoCopy
	}
	if profile.Mirrors != nil {
		clone.Mirrors = append([]string(nil), profile.Mirrors...)
	}
	if profile.Nodes != nil {
		clone.Nodes = append([]*proxyconfig.ProxyConfig(nil), profile.Nodes...)
	}
	if profile.SourceHealthByURL != nil {
		clone.SourceHealthByURL = make(map[string]SourceHealth, len(profile.SourceHealthByURL))
		for key, value := range profile.SourceHealthByURL {
			clone.SourceHealthByURL[key] = value
		}
	}
	if profile.SourceValidatorsByURL != nil {
		clone.SourceValidatorsByURL = make(map[string]SourceValidator, len(profile.SourceValidatorsByURL))
		for key, value := range profile.SourceValidatorsByURL {
			clone.SourceValidatorsByURL[key] = value
		}
	}
	return clone
}

func applyPatch(profile *ManagedProfile, patch *ProfilePatch) {
	if patch.Name != nil {
		profile.Name = *patch.Name
	}
	if patch.URL != nil {
		profile.URL = strings.TrimSpace(*patch.URL)
	}
	if patch.Mirrors != nil {
		profile.Mirrors = append([]string(nil), *patch.Mirrors...)
	}
	if patch.UpdateIntervalH != nil {
		profile.UpdateIntervalH = *patch.UpdateIntervalH
	}
	if patch.Active != nil {
		profile.Active = *patch.Active
	}
	if patch.AutoRefresh != nil {
		profile.AutoRefresh = *patch.AutoRefresh
	}
	if patch.RemoteFetchEnabled != nil {
		profile.RemoteFetchEnabled = *patch.RemoteFetchEnabled
	}
}

// profileSources lists the primary URL followed by normalized mirrors.
func profileSources(profile ManagedProfile) []string {
	out := make([]string, 0, 1+len(profile.Mirrors))
	if primary := strings.TrimSpace(profile.URL); primary != "" {
		out = append(out, primary)
	}
	out = append(out, normalizeProfileMirrors(profile.URL, profile.Mirrors)...)
	return out
}

// orderedProfileSources orders eligible sources: the last good source first,
// then remaining sources in declared order, skipping gated ones.
func orderedProfileSources(profile ManagedProfile, now time.Time) []string {
	sources := profileSources(profile)
	last := strings.TrimSpace(profile.LastSourceURL)
	ordered := make([]string, 0, len(sources))
	appendIfEligible := func(source string) {
		health := profile.SourceHealthByURL[source]
		if health.NextEligibleAt.IsZero() || !now.Before(health.NextEligibleAt) {
			ordered = append(ordered, source)
		}
	}
	if last != "" && profileContainsSource(profile, last) {
		appendIfEligible(last)
	}
	for _, source := range sources {
		if source != last {
			appendIfEligible(source)
		}
	}
	return ordered
}

func profileHasEligibleSource(profile ManagedProfile, now time.Time) bool {
	return len(orderedProfileSources(profile, now)) > 0
}

func profileContainsSource(profile ManagedProfile, source string) bool {
	if profile.URL == source {
		return true
	}
	for _, mirror := range profile.Mirrors {
		if mirror == source {
			return true
		}
	}
	return false
}

// profileRefreshDue reports whether automatic refresh should run now. The
// aggregate SourceHealth mirror is deliberately ignored: eligibility consults
// per-source gates only.
func profileRefreshDue(profile ManagedProfile, now time.Time) bool {
	if !profile.Active || !profile.RemoteFetchEnabled || !profile.AutoRefresh || profile.UpdateIntervalH <= 0 {
		return false
	}
	if !profileHasEligibleSource(profile, now) {
		return false
	}
	if profile.LastUpdated.IsZero() {
		return true
	}
	const maxHours = int((1<<63 - 1) / int64(time.Hour))
	if profile.UpdateIntervalH > maxHours {
		return false
	}
	next := profile.LastUpdated.Add(time.Duration(profile.UpdateIntervalH) * time.Hour)
	return !now.Before(next)
}

// earliestEligibleAt returns the soonest NextEligibleAt among still-gated
// sources, ignoring sources that are already eligible again.
func earliestEligibleAt(profile ManagedProfile, now time.Time) time.Time {
	var earliest time.Time
	for _, source := range profileSources(profile) {
		health := profile.SourceHealthByURL[source]
		if health.NextEligibleAt.IsZero() || !now.Before(health.NextEligibleAt) {
			continue
		}
		if earliest.IsZero() || health.NextEligibleAt.Before(earliest) {
			earliest = health.NextEligibleAt
		}
	}
	return earliest
}

// normalizeProfileMirrors trims, drops empties/invalids/duplicates/primary,
// enforces the URL length cap, and bounds the list to maxProfileMirrors while
// preserving declared order.
func normalizeProfileMirrors(primary string, mirrors []string) []string {
	seen := make(map[string]struct{}, len(mirrors)+1)
	if trimmed := strings.TrimSpace(primary); trimmed != "" {
		seen[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(mirrors))
	for _, mirror := range mirrors {
		mirror = strings.TrimSpace(mirror)
		if mirror == "" {
			continue
		}
		if _, duplicate := seen[mirror]; duplicate {
			continue
		}
		if len(mirror) > maxProfileSourceURLLen || ValidateProfileSourceURL(mirror) != nil {
			continue
		}
		seen[mirror] = struct{}{}
		out = append(out, mirror)
		if len(out) >= maxProfileMirrors {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// pruneSourceHealth keeps only entries for surviving sources.
func pruneSourceHealth(primary string, mirrors []string, health map[string]SourceHealth) map[string]SourceHealth {
	return pruneSourceMap(primary, mirrors, health,
		func(out map[string]SourceHealth, key string) { out[key] = health[key] })
}

// pruneSourceValidators keeps only validator entries for surviving sources.
func pruneSourceValidators(primary string, mirrors []string, validators map[string]SourceValidator) map[string]SourceValidator {
	return pruneSourceMap(primary, mirrors, validators,
		func(out map[string]SourceValidator, key string) { out[key] = validators[key] })
}

func pruneSourceMap[V any](primary string, mirrors []string, source map[string]V, copy func(map[string]V, string)) map[string]V {
	if len(source) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, 1+len(mirrors))
	if trimmed := strings.TrimSpace(primary); trimmed != "" {
		allowed[trimmed] = struct{}{}
	}
	for _, mirror := range mirrors {
		if mirror = strings.TrimSpace(mirror); mirror != "" {
			allowed[mirror] = struct{}{}
		}
	}
	pruned := make(map[string]V, len(source))
	for key := range source {
		if _, keep := allowed[key]; keep {
			copy(pruned, key)
		}
	}
	if len(pruned) == 0 {
		return nil
	}
	return pruned
}

func validateProfileURLs(profile ManagedProfile) error {
	if strings.TrimSpace(profile.URL) == "" {
		return fmt.Errorf("profile URL is required")
	}
	return ValidateProfileSourceURL(profile.URL)
}

// fetchProfileSource issues the bounded fetch, upgrading to a conditional
// request whenever an accepted validator exists and the client supports it.
func fetchProfileSource(ctx context.Context, client ProfileFetcher, sourceURL string, validator SourceValidator) (EgressResponse, error) {
	if client == nil {
		return EgressResponse{}, ErrRemoteFetchDisabled
	}
	etag := normalizeSourceETag(validator.ETag)
	if etag == "" {
		return client.Fetch(ctx, sourceURL)
	}
	if conditional, ok := client.(conditionalFetchClient); ok {
		return conditional.FetchConditional(ctx, sourceURL, etag)
	}
	return client.Fetch(ctx, sourceURL)
}

// headerValue returns the first value of a header field matched
// case-insensitively over the raw map. Header.Get alone misses keys stored
// under a non-canonical literal spelling.
func headerValue(header http.Header, name string) string {
	if header == nil {
		return ""
	}
	for key, values := range header {
		if len(values) == 0 || !strings.EqualFold(key, name) {
			continue
		}
		return strings.TrimSpace(values[0])
	}
	return ""
}

// profileInfoFromHeaders extracts optional announcement metadata and a
// refreshed display name from subscription response headers.
func profileInfoFromHeaders(header http.Header) (*ProfileInfo, string) {
	name := headerValue(header, "X-Profile-Name")
	title := headerValue(header, "X-Subscription-Title")
	var info *ProfileInfo
	if title != "" {
		info = &ProfileInfo{Announcement: title}
	}
	if name == "" && info != nil {
		name = info.Announcement
	}
	return info, name
}

func sourceValidatorFromHeaders(header http.Header) SourceValidator {
	return SourceValidator{
		ETag:         headerValue(header, "ETag"),
		LastModified: headerValue(header, "Last-Modified"),
	}
}

// sourceLabel strips query strings before diagnostics surface a source URL.
func sourceLabel(sourceURL string) string {
	if idx := strings.Index(sourceURL, "?"); idx >= 0 {
		sourceURL = sourceURL[:idx]
	}
	return sourceURL
}

// boundedSourceError redacts secrets from the error text and bounds its
// length so provider tokens in URLs never persist in stored evidence.
func boundedSourceError(err error) string {
	if err == nil {
		return ""
	}
	message := redact.String(err.Error())
	if len(message) <= maxSourceErrorLen {
		return message
	}
	truncated := message[:maxSourceErrorLen]
	for !utf8.ValidString(truncated) && len(truncated) > 0 {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated + "…"
}

// sourceRetryAfterDelay parses a server Retry-After hint (delta-seconds or
// HTTP-date) into a bounded delay; unparsable or past hints yield zero.
func sourceRetryAfterDelay(headers http.Header, now time.Time) time.Duration {
	value := headerValue(headers, "Retry-After")
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds > int64(profileSourceRetryAfterCap/time.Second) {
			return profileSourceRetryAfterCap
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	delay := when.Sub(now)
	if delay <= 0 {
		return 0
	}
	if delay > profileSourceRetryAfterCap {
		return profileSourceRetryAfterCap
	}
	return delay
}

// profileSourceBackoff doubles from the base for each consecutive failure,
// capped at profileSourceRetryAfterCap.
func profileSourceBackoff(consecutive int) time.Duration {
	backoff := profileSourceBackoffBase
	for i := 1; i < consecutive && backoff < profileSourceRetryAfterCap; i++ {
		backoff *= 2
	}
	if backoff > profileSourceRetryAfterCap {
		backoff = profileSourceRetryAfterCap
	}
	return backoff
}
