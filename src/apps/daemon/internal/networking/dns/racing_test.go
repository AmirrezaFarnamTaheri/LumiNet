package dns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockResolver is a simple UpstreamResolver for testing.
type mockResolver struct {
	id       string
	delay    time.Duration
	respBody []byte
	respErr  error
	mu       sync.Mutex
	calls    int
}

func (m *mockResolver) Query(ctx context.Context, question string) ([]byte, time.Duration, error) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	select {
	case <-time.After(m.delay):
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
	return m.respBody, m.delay, m.respErr
}

func (m *mockResolver) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestRacingResolver_RaceReturnsFastest(t *testing.T) {
	t.Parallel()
	cfg := RacingConfig{
		Upstreams: []RacingUpstream{
			{ID: "fast", Name: "Fast", Weight: 1, Resolver: &mockResolver{id: "fast", delay: 10 * time.Millisecond, respBody: []byte("fast-response")}},
			{ID: "slow", Name: "Slow", Weight: 1, Resolver: &mockResolver{id: "slow", delay: 500 * time.Millisecond, respBody: []byte("slow-response")}},
		},
		Timeout: 2 * time.Second,
		Jitter:  5 * time.Millisecond,
	}
	r := NewRacingResolver(cfg)
	ctx := context.Background()
	resp, err := r.Race(ctx, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp) != "fast-response" {
		t.Errorf("expected fast-response, got %q", string(resp))
	}
}

func TestRacingResolver_AllFailReturnsAggregatedError(t *testing.T) {
	t.Parallel()
	cfg := RacingConfig{
		Upstreams: []RacingUpstream{
			{ID: "a", Name: "A", Weight: 1, Resolver: &mockResolver{id: "a", delay: 1 * time.Millisecond, respErr: errors.New("a failed")}},
			{ID: "b", Name: "B", Weight: 1, Resolver: &mockResolver{id: "b", delay: 2 * time.Millisecond, respErr: errors.New("b failed")}},
		},
		Timeout: 200 * time.Millisecond,
		Jitter:  1 * time.Millisecond,
	}
	r := NewRacingResolver(cfg)
	ctx := context.Background()
	_, err := r.Race(ctx, "example.com")
	if err == nil {
		t.Fatal("expected an aggregated error")
	}
}

func TestRacingResolver_SkipsZeroWeight(t *testing.T) {
	t.Parallel()
	cfg := RacingConfig{
		Upstreams: []RacingUpstream{
			{ID: "zero", Name: "Zero", Weight: 0, Resolver: &mockResolver{id: "zero", delay: 1 * time.Millisecond, respBody: []byte("zero-should-not-be-called")}},
			{ID: "one", Name: "One", Weight: 1, Resolver: &mockResolver{id: "one", delay: 100 * time.Millisecond, respBody: []byte("one-response")}},
		},
		Timeout: 2 * time.Second,
	}
	r := NewRacingResolver(cfg)
	ctx := context.Background()
	resp, err := r.Race(ctx, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp) != "one-response" {
		t.Errorf("unexpected response: %q", string(resp))
	}
	// zero-weight upstream should not have been called.
	zero := cfg.Upstreams[0].Resolver.(*mockResolver)
	if zero.Calls() != 0 {
		t.Errorf("zero-weight upstream should not be called, got %d calls", zero.Calls())
	}
}

func TestRacingResolver_ContextCancelled(t *testing.T) {
	t.Parallel()
	cfg := RacingConfig{
		Upstreams: []RacingUpstream{
			{ID: "slow", Name: "Slow", Weight: 1, Resolver: &mockResolver{id: "slow", delay: 10 * time.Second, respBody: []byte("never")}},
		},
		Timeout: 10 * time.Second,
		Jitter:  1 * time.Millisecond,
	}
	r := NewRacingResolver(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := r.Race(ctx, "example.com")
	if err == nil {
		t.Error("expected error when context is cancelled")
	}
}

func TestRacingResolver_ExponentialBackoff(t *testing.T) {
	t.Parallel()
	cfg := RacingConfig{
		Upstreams: []RacingUpstream{
			{ID: "flaky", Name: "Flaky", Weight: 1, Resolver: &mockResolver{id: "flaky", delay: 1 * time.Millisecond, respErr: errors.New("flaky")}},
		},
		Timeout:     1 * time.Second,
		MaxFailures: 2,
	}
	r := NewRacingResolver(cfg)
	ctx := context.Background()
	// Trigger enough failures to enter backoff.
	for i := 0; i < 3; i++ {
		r.Race(ctx, "example.com")
	}
	inBackoff, remaining := r.BackoffStatus("flaky")
	if !inBackoff {
		t.Error("expected upstream to be in backoff")
	}
	if remaining <= 0 {
		t.Error("expected positive remaining backoff duration")
	}
	// Successful query clears backoff.
	cfg.Upstreams[0].Resolver = &mockResolver{id: "flaky", delay: 1 * time.Millisecond, respBody: []byte("ok")}
	r = NewRacingResolver(cfg)
	r.backoff.state["flaky"] = &upstreamBackoffState{failures: 10, backoffUntil: time.Now().Add(time.Hour)}
	r.backoff.RecordSuccess("flaky")
	if _, remaining := r.BackoffStatus("flaky"); remaining > 0 {
		t.Error("success should clear backoff")
	}
}

func TestRacingResolver_AddRemoveUpstream(t *testing.T) {
	t.Parallel()
	cfg := RacingConfig{
		Upstreams: []RacingUpstream{
			{ID: "a", Name: "A", Weight: 1, Resolver: &mockResolver{id: "a", delay: 100 * time.Millisecond, respBody: []byte("a")}},
		},
		Timeout: 2 * time.Second,
	}
	r := NewRacingResolver(cfg)
	r.AddUpstream(RacingUpstream{ID: "b", Name: "B", Weight: 1, Resolver: &mockResolver{id: "b", delay: 10 * time.Millisecond, respBody: []byte("b")}})
	resp, _ := r.Race(context.Background(), "x")
	if string(resp) != "b" {
		t.Errorf("expected 'b', got %q", string(resp))
	}
	r.RemoveUpstream("b")
	resp, err := r.Race(context.Background(), "x")
	if err != nil {
		t.Logf("error (expected with single upstream): %v", err)
	}
}

func TestRacingResolver_TimeoutGetterSetter(t *testing.T) {
	t.Parallel()
	cfg := RacingConfig{Timeout: 5 * time.Second}
	r := NewRacingResolver(cfg)
	if r.GetTimeout() != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", r.GetTimeout())
	}
	r.SetTimeout(10 * time.Second)
	if r.GetTimeout() != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", r.GetTimeout())
	}
}

func TestRacingResolver_JitterGetterSetter(t *testing.T) {
	t.Parallel()
	cfg := RacingConfig{Jitter: 20 * time.Millisecond}
	r := NewRacingResolver(cfg)
	if r.GetJitter() != 20*time.Millisecond {
		t.Errorf("expected 20ms jitter, got %v", r.GetJitter())
	}
	r.SetJitter(100 * time.Millisecond)
	if r.GetJitter() != 100*time.Millisecond {
		t.Errorf("expected 100ms jitter, got %v", r.GetJitter())
	}
}
