package sub

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type sequenceProfileFetcher struct {
	responses []EgressResponse
	errors    []error
	calls     int
}

func (f *sequenceProfileFetcher) Fetch(context.Context, string) (EgressResponse, error) {
	idx := f.calls
	f.calls++
	if idx < len(f.errors) && f.errors[idx] != nil {
		return EgressResponse{}, f.errors[idx]
	}
	if idx < len(f.responses) {
		return f.responses[idx], nil
	}
	return EgressResponse{StatusCode: http.StatusOK}, nil
}

func TestProfileSourceHealthBackoffAndRecovery(t *testing.T) {
	secret := "super-secret-token"
	fetcher := &sequenceProfileFetcher{
		errors: []error{
			errors.New("fetch https://example.test/sub?token=" + secret + " failed token=" + secret),
			nil,
			nil,
		},
		responses: []EgressResponse{
			{},
			{StatusCode: http.StatusOK, Header: http.Header{}, Body: []byte("not-a-proxy-line")},
			{StatusCode: http.StatusOK, Header: http.Header{}, Body: []byte("ss://YWVzLTEyOC1nY206cGFzc0BleGFtcGxlLmNvbTo0NDM=")},
		},
	}
	service := newProfileService(context.Background(), fetcher)
	service.Create(ManagedProfile{
		ID:                 "profile-1",
		URL:                "https://example.test/sub?token=" + secret,
		Active:             true,
		RemoteFetchEnabled: true,
	})

	if _, err := service.Refresh(context.Background(), "profile-1"); err == nil {
		t.Fatal("first refresh unexpectedly succeeded")
	}
	failed, _ := service.Get("profile-1")
	if failed.SourceHealth.ConsecutiveFailures != 1 {
		t.Fatalf("failures=%d, want 1", failed.SourceHealth.ConsecutiveFailures)
	}
	if failed.SourceHealth.LastAttemptAt.IsZero() || failed.SourceHealth.NextEligibleAt.IsZero() {
		t.Fatalf("missing failure timestamps: %+v", failed.SourceHealth)
	}
	if got := failed.SourceHealth.NextEligibleAt.Sub(failed.SourceHealth.LastAttemptAt); got != profileSourceBackoffBase {
		t.Fatalf("backoff=%v, want %v", got, profileSourceBackoffBase)
	}
	if strings.Contains(failed.SourceHealth.LastError, secret) {
		t.Fatalf("source-health error leaked secret: %q", failed.SourceHealth.LastError)
	}

	if _, err := service.Refresh(context.Background(), "profile-1"); err == nil {
		t.Fatal("invalid subscription payload unexpectedly marked source healthy")
	}
	invalid, _ := service.Get("profile-1")
	if invalid.SourceHealth.ConsecutiveFailures != 2 || !invalid.LastUpdated.IsZero() {
		t.Fatalf("invalid payload changed accepted freshness: %+v", invalid)
	}

	refreshed, err := service.Refresh(context.Background(), "profile-1")
	if err != nil {
		t.Fatalf("third refresh error = %v", err)
	}
	if refreshed.SourceHealth.ConsecutiveFailures != 0 || refreshed.SourceHealth.LastSuccessAt.IsZero() || refreshed.SourceHealth.LastError != "" || !refreshed.SourceHealth.NextEligibleAt.IsZero() {
		t.Fatalf("success did not reset health: %+v", refreshed.SourceHealth)
	}
}

func TestQueueDueRefreshesRespectsBackoffAndInflightOwnership(t *testing.T) {
	fetcher := newBlockingProfileFetcher()
	service := newProfileService(context.Background(), fetcher)
	now := time.Now().UTC()
	service.Create(ManagedProfile{
		ID:                 "due",
		URL:                "https://example.test/due",
		LastUpdated:        now.Add(-2 * time.Hour),
		UpdateIntervalH:    1,
		Active:             true,
		RemoteFetchEnabled: true,
		AutoRefresh:        true,
	})
	createdBackoff := service.Create(ManagedProfile{
		ID:                 "backoff",
		URL:                "https://example.test/backoff",
		LastUpdated:        now.Add(-2 * time.Hour),
		UpdateIntervalH:    1,
		Active:             true,
		RemoteFetchEnabled: true,
		AutoRefresh:        true,
	})
	// Seed the gate on the per-source record the scheduler consults; the
	// aggregate field is a derived mirror and is not read for eligibility.
	service.mu.Lock()
	stored := service.profiles["backoff"]
	stored.SourceHealthByURL = map[string]SourceHealth{
		"https://example.test/backoff": {
			ConsecutiveFailures: 2,
			NextEligibleAt:      now.Add(time.Minute),
		},
	}
	service.profiles["backoff"] = stored
	service.mu.Unlock()
	_ = createdBackoff

	if got := service.QueueDueRefreshes(now); got != 1 {
		t.Fatalf("queued=%d, want 1", got)
	}
	<-fetcher.started
	if got := service.QueueDueRefreshes(now.Add(time.Second)); got != 0 {
		t.Fatalf("second queued=%d, want 0 while due refresh is in flight", got)
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestProfileURLChangeClearsSourceDerivedState(t *testing.T) {
	service := NewProfileService()
	service.Create(ManagedProfile{
		ID:          "profile-1",
		URL:         "https://old.example.test/sub",
		LastUpdated: time.Now().UTC(),
		NodeCount:   42,
		Info:        &ProfileInfo{Announcement: "old source"},
		SourceHealth: SourceHealth{
			ConsecutiveFailures: 3,
			LastError:           "old error",
		},
		SourceValidatorsByURL: map[string]SourceValidator{"https://old.example.test/sub": {ETag: `"old"`}},
	})
	newURL := "https://new.example.test/sub"
	updated, ok := service.Update("profile-1", ProfilePatch{URL: &newURL})
	if !ok {
		t.Fatal("profile update failed")
	}
	if !updated.LastUpdated.IsZero() || updated.NodeCount != 0 || updated.Info != nil || updated.SourceHealth.ConsecutiveFailures != 0 || updated.SourceHealth.LastError != "" || len(updated.SourceValidatorsByURL) != 0 {
		t.Fatalf("old source state survived URL change: %+v", updated)
	}
}

func TestQueueRefreshEligibilityRechecksCurrentProfileState(t *testing.T) {
	service := newProfileService(context.Background(), &sequenceProfileFetcher{})
	now := time.Now().UTC()
	service.Create(ManagedProfile{
		ID:                 "profile-1",
		URL:                "https://example.test/sub",
		LastUpdated:        now.Add(-2 * time.Hour),
		UpdateIntervalH:    1,
		Active:             true,
		RemoteFetchEnabled: true,
		AutoRefresh:        true,
	})

	// Model the scheduler's stale snapshot: the profile was due when observed,
	// but is disabled before refresh ownership is installed.
	stale, _ := service.Get("profile-1")
	if !profileRefreshDue(stale, now) {
		t.Fatal("test profile should be due before deactivation")
	}
	inactive := false
	if _, ok := service.Update("profile-1", ProfilePatch{Active: &inactive}); !ok {
		t.Fatal("profile update failed")
	}
	if service.queueRefresh("profile-1", false, func(current ManagedProfile) bool {
		return profileRefreshDue(current, now)
	}) {
		t.Fatal("stale automatic-refresh snapshot queued after profile was deactivated")
	}
}

func TestProfileRefreshDueRejectsOverflowingInterval(t *testing.T) {
	now := time.Now().UTC()
	profile := ManagedProfile{
		LastUpdated:        now.Add(-time.Hour),
		UpdateIntervalH:    int(^uint(0) >> 1),
		Active:             true,
		RemoteFetchEnabled: true,
		AutoRefresh:        true,
	}
	if profileRefreshDue(profile, now) {
		t.Fatal("overflowing update interval must not become immediately due")
	}
}

func TestQueueDueRefreshesRequiresAutoRefreshOptIn(t *testing.T) {
	service := newProfileService(context.Background(), &sequenceProfileFetcher{})
	now := time.Now().UTC()
	service.Create(ManagedProfile{
		ID:                 "manual-only",
		URL:                "https://example.test/manual",
		LastUpdated:        now.Add(-2 * time.Hour),
		UpdateIntervalH:    1,
		Active:             true,
		RemoteFetchEnabled: true,
		AutoRefresh:        false,
	})
	if got := service.QueueDueRefreshes(now); got != 0 {
		t.Fatalf("queued=%d, want 0 without auto-refresh opt-in", got)
	}
}

func TestProfileRefreshFallsBackToMirrorAndPrefersLastGoodSource(t *testing.T) {
	fetcher := &recordingProfileFetcher{
		responses: map[string][]EgressResponse{
			"https://mirror.example/sub": {{StatusCode: 200, Body: []byte("ss://YWVzLTEyOC1nY206cGFzc0BleGFtcGxlLmNvbTo0NDM=")}},
		},
		errors: map[string][]error{
			"https://primary.example/sub": {errors.New("primary unavailable")},
		},
	}
	service := newProfileService(context.Background(), fetcher)
	service.Create(ManagedProfile{
		ID: "profile-1", URL: "https://primary.example/sub",
		Mirrors: []string{"https://mirror.example/sub"}, RemoteFetchEnabled: true,
	})

	got, err := service.Refresh(context.Background(), "profile-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.LastSourceURL != "https://mirror.example/sub" {
		t.Fatalf("last source=%q, want mirror", got.LastSourceURL)
	}
	if health := got.SourceHealthByURL["https://primary.example/sub"]; health.ConsecutiveFailures != 1 {
		t.Fatalf("primary health=%+v, want one failure", health)
	}
	if health := got.SourceHealthByURL["https://mirror.example/sub"]; health.LastSuccessAt.IsZero() {
		t.Fatalf("mirror success missing: %+v", health)
	}

	fetcher.resetCalls()
	if _, err := service.Refresh(context.Background(), "profile-1"); err != nil {
		t.Fatal(err)
	}
	calls := fetcher.callsSnapshot()
	if len(calls) == 0 || calls[0] != "https://mirror.example/sub" {
		t.Fatalf("refresh order=%v, want last-good mirror first", calls)
	}
}

func TestProfileMirrorsAreBoundedDedupedAndCloned(t *testing.T) {
	service := NewProfileService()
	created := service.Create(ManagedProfile{
		ID: "profile-1", URL: "https://primary.example/sub",
		Mirrors: []string{
			" https://mirror-1.example/sub ",
			"https://primary.example/sub",
			"https://mirror-1.example/sub",
			"https://mirror-2.example/sub",
			"https://mirror-3.example/sub",
			"https://mirror-4.example/sub",
		},
	})
	want := []string{"https://mirror-1.example/sub", "https://mirror-2.example/sub", "https://mirror-3.example/sub"}
	if !slices.Equal(created.Mirrors, want) {
		t.Fatalf("mirrors=%v, want %v", created.Mirrors, want)
	}
	created.Mirrors[0] = "mutated"
	stored, _ := service.Get("profile-1")
	if stored.Mirrors[0] != want[0] {
		t.Fatalf("stored mirrors mutated through snapshot: %v", stored.Mirrors)
	}
}

type conditionalRecordingFetcher struct {
	response EgressResponse
	etag     string
	calls    int
}

func (f *conditionalRecordingFetcher) Fetch(context.Context, string) (EgressResponse, error) {
	f.calls++
	return f.response, nil
}

func (f *conditionalRecordingFetcher) FetchConditional(_ context.Context, _ string, etag string) (EgressResponse, error) {
	f.calls++
	f.etag = etag
	return f.response, nil
}

func TestProfileConditionalRefreshUsesAcceptedETagAndPreservesContentOn304(t *testing.T) {
	oldUpdated := time.Unix(1_700_000_000, 0).UTC()
	fetcher := &conditionalRecordingFetcher{response: EgressResponse{
		StatusCode: http.StatusNotModified,
		Header:     http.Header{"ETag": []string{`"v2"`}},
	}}
	service := newProfileService(context.Background(), fetcher)
	service.Create(ManagedProfile{
		ID:                 "profile-etag",
		URL:                "https://example.test/sub",
		Name:               "accepted",
		NodeCount:          7,
		LastUpdated:        oldUpdated,
		Info:               &ProfileInfo{Announcement: "keep-me"},
		RemoteFetchEnabled: true,
		SourceValidatorsByURL: map[string]SourceValidator{
			"https://example.test/sub": {ETag: `"v1"`},
		},
	})

	updated, err := service.Refresh(context.Background(), "profile-etag")
	if err != nil {
		t.Fatal(err)
	}
	if fetcher.etag != `"v1"` {
		t.Fatalf("conditional etag=%q, want accepted v1", fetcher.etag)
	}
	if !updated.LastUpdated.After(oldUpdated) || updated.NodeCount != 7 || updated.Name != "accepted" || updated.Info == nil || updated.Info.Announcement != "keep-me" {
		t.Fatalf("304 changed accepted content: %+v", updated)
	}
	if got := updated.SourceValidatorsByURL[updated.URL].ETag; got != `"v2"` {
		t.Fatalf("validator=%q, want v2", got)
	}
	if updated.SourceHealth.ConsecutiveFailures != 0 || updated.SourceHealth.LastSuccessAt.IsZero() {
		t.Fatalf("304 did not record source success: %+v", updated.SourceHealth)
	}
}

func TestProfileInvalidPayloadPreservesLastKnownGoodAndValidator(t *testing.T) {
	oldUpdated := time.Unix(1_700_000_000, 0).UTC()
	fetcher := &conditionalRecordingFetcher{response: EgressResponse{
		StatusCode: http.StatusOK,
		Header:     http.Header{"ETag": []string{`"bad-new"`}},
		Body:       []byte("not-a-subscription"),
	}}
	service := newProfileService(context.Background(), fetcher)
	service.Create(ManagedProfile{
		ID:                 "profile-lkg",
		URL:                "https://example.test/sub",
		Name:               "last-known-good",
		NodeCount:          11,
		LastUpdated:        oldUpdated,
		Info:               &ProfileInfo{Announcement: "trusted-old"},
		RemoteFetchEnabled: true,
		SourceValidatorsByURL: map[string]SourceValidator{
			"https://example.test/sub": {ETag: `"good-old"`},
		},
	})

	if _, err := service.Refresh(context.Background(), "profile-lkg"); err == nil {
		t.Fatal("invalid payload unexpectedly accepted")
	}
	current, _ := service.Get("profile-lkg")
	if !current.LastUpdated.Equal(oldUpdated) || current.NodeCount != 11 || current.Name != "last-known-good" || current.Info == nil || current.Info.Announcement != "trusted-old" {
		t.Fatalf("invalid payload replaced last-known-good state: %+v", current)
	}
	if got := current.SourceValidatorsByURL[current.URL].ETag; got != `"good-old"` {
		t.Fatalf("invalid payload replaced validator: %q", got)
	}
	if current.SourceHealth.ConsecutiveFailures != 1 || current.SourceHealth.LastError == "" {
		t.Fatalf("invalid payload not recorded as source failure: %+v", current.SourceHealth)
	}
}

type recordingProfileFetcher struct {
	mu        sync.Mutex
	responses map[string][]EgressResponse
	errors    map[string][]error
	calls     []string
}

func (f *recordingProfileFetcher) Fetch(_ context.Context, url string) (EgressResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, url)
	if errs := f.errors[url]; len(errs) > 0 {
		err := errs[0]
		f.errors[url] = errs[1:]
		return EgressResponse{}, err
	}
	if responses := f.responses[url]; len(responses) > 0 {
		resp := responses[0]
		if len(responses) > 1 {
			f.responses[url] = responses[1:]
		}
		return resp, nil
	}
	return EgressResponse{StatusCode: 200, Body: []byte("ss://YWVzLTEyOC1nY206cGFzc0BleGFtcGxlLmNvbTo0NDM=")}, nil
}

func (f *recordingProfileFetcher) resetCalls() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}

func (f *recordingProfileFetcher) callsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func TestProfileMirrorsRejectInternalOversizeAndClearRemovedLastSource(t *testing.T) {
	service := newProfileService(context.Background(), &sequenceProfileFetcher{})
	primary := "https://primary.example/sub"
	mirror := "https://mirror.example/sub"
	created := service.Create(ManagedProfile{ID: "bounded-mirrors", URL: primary, Mirrors: []string{mirror, "https://" + strings.Repeat("x", maxProfileSourceURLLen)}})
	if len(created.Mirrors) != 1 || created.Mirrors[0] != mirror {
		t.Fatalf("mirrors=%v", created.Mirrors)
	}
	service.mu.Lock()
	profile := service.profiles["bounded-mirrors"]
	profile.LastSourceURL = mirror
	service.profiles[profile.ID] = profile
	service.mu.Unlock()
	empty := []string{}
	updated, ok := service.Update(profile.ID, ProfilePatch{Mirrors: &empty})
	if !ok {
		t.Fatal("profile missing")
	}
	if updated.LastSourceURL != "" {
		t.Fatalf("stale last source retained: %q", updated.LastSourceURL)
	}
}

func TestRecordRefreshFailureCompatibilityDelegatesToPrimarySourceHealth(t *testing.T) {
	svc := newProfileService(context.Background(), &sequenceProfileFetcher{})
	profile := svc.Create(ManagedProfile{
		ID: "compat-primary", URL: "https://primary.example/sub", RemoteFetchEnabled: true,
	})
	at := time.Unix(1_700_000_123, 0).UTC()
	svc.recordRefreshFailure(profile.ID, profile.URL, errors.New("primary unavailable"), at)
	got, ok := svc.Get(profile.ID)
	if !ok {
		t.Fatal("profile missing")
	}
	health := got.SourceHealthByURL[profile.URL]
	if health.ConsecutiveFailures != 1 || !health.LastAttemptAt.Equal(at) {
		t.Fatalf("primary source health=%+v", health)
	}
	if got.SourceHealth.ConsecutiveFailures != 1 {
		t.Fatalf("aggregate source health=%+v", got.SourceHealth)
	}
}

func TestSourceRetryAfterDelayParsesAndBoundsServerHints(t *testing.T) {
	now := time.Date(2026, 8, 14, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "delta-seconds", value: "120", want: 2 * time.Minute},
		{name: "http-date", value: now.Add(3 * time.Minute).Format(http.TimeFormat), want: 3 * time.Minute},
		{name: "past", value: now.Add(-time.Minute).Format(http.TimeFormat), want: 0},
		{name: "invalid", value: "tomorrow-ish", want: 0},
		{name: "negative", value: "-1", want: 0},
		{name: "bounded", value: "999999999", want: profileSourceRetryAfterCap},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{"Retry-After": []string{tt.value}}
			if got := sourceRetryAfterDelay(header, now); got != tt.want {
				t.Fatalf("delay=%s, want %s", got, tt.want)
			}
		})
	}
}

func TestRecordSourceFailureHonorsServerMinimumDelay(t *testing.T) {
	now := time.Date(2026, 8, 14, 8, 0, 0, 0, time.UTC)
	service := NewProfileService()
	profile := service.Create(ManagedProfile{ID: "p", URL: "https://primary.example/sub", Mirrors: []string{"https://mirror.example/sub"}})
	service.recordSourceFailureWithMinimumDelay(profile.ID, profile.URL, profile.URL, errors.New("429"), now, 5*time.Minute)
	got, ok := service.Get(profile.ID)
	if !ok {
		t.Fatal("profile disappeared")
	}
	health := got.SourceHealthByURL[profile.URL]
	if want := now.Add(5 * time.Minute); !health.NextEligibleAt.Equal(want) {
		t.Fatalf("next eligible=%s, want %s", health.NextEligibleAt, want)
	}
	if got.SourceHealth.NextEligibleAt.IsZero() || got.SourceHealth.NextEligibleAt.After(health.NextEligibleAt) {
		t.Fatalf("aggregate source health does not preserve earliest eligibility: %+v", got.SourceHealth)
	}
}
