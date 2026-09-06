package remoteaction

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdempotentRetriesRetryableStatus(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "later", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	policy := DefaultPolicy("test.idempotent", Idempotent)
	policy.BaseDelay = time.Millisecond
	outcome, err := Do(context.Background(), server.Client(), policy, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, server.URL, strings.NewReader("desired"))
	}, nil)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer outcome.Response.Body.Close()
	if outcome.Attempts != 3 || calls.Load() != 3 {
		t.Fatalf("attempts=%d calls=%d, want 3", outcome.Attempts, calls.Load())
	}
}

func TestReconcilePreventsDuplicateReplay(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("connection reset after write")
	})}
	var reconciles atomic.Int32
	policy := DefaultPolicy("test.create", ReconcileBeforeRetry)
	outcome, err := Do(context.Background(), client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/create", strings.NewReader("x"))
	}, func(context.Context) (bool, error) {
		reconciles.Add(1)
		return true, nil
	})
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if !outcome.Reconciled || outcome.Attempts != 1 || calls.Load() != 1 || reconciles.Load() != 1 {
		t.Fatalf("unexpected outcome=%+v calls=%d reconciles=%d", outcome, calls.Load(), reconciles.Load())
	}
}

func TestReconcileReleasesRetryResponseBeforeReadback(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/create":
			posts.Add(1)
			w.Header().Set("Retry-After", "0")
			http.Error(w, "ambiguous", http.StatusServiceUnavailable)
		case "/state":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = 1
	client := &http.Client{Transport: transport}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	policy := DefaultPolicy("test.create", ReconcileBeforeRetry)
	outcome, err := Do(ctx, client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/create", strings.NewReader("x"))
	}, func(ctx context.Context) (bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/state", nil)
		if err != nil {
			return false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK, nil
	})
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if !outcome.Reconciled || outcome.Attempts != 1 || posts.Load() != 1 {
		t.Fatalf("outcome=%+v posts=%d, want reconciled after one create", outcome, posts.Load())
	}
}

func TestReconcileFailureFailsClosed(t *testing.T) {
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("timeout")
	})}
	policy := DefaultPolicy("test.create", ReconcileBeforeRetry)
	_, err := Do(context.Background(), client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/create", nil)
	}, func(context.Context) (bool, error) {
		return false, errors.New("readback unavailable")
	})
	if err == nil || !strings.Contains(err.Error(), "state uncertain") {
		t.Fatalf("error = %v, want fail-closed state-uncertain error", err)
	}
}

func TestSingleAttemptNeverReplays(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("timeout")
	})}
	policy := DefaultPolicy("test.side-effect", SingleAttempt)
	_, err := Do(context.Background(), client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/side-effect", nil)
	}, nil)
	if err == nil || calls.Load() != 1 {
		t.Fatalf("error=%v calls=%d, want one attempt", err, calls.Load())
	}
}

func TestRetryAfterIsCapped(t *testing.T) {
	delay, ok := parseRetryAfter("120", time.Now(), 5*time.Second)
	if !ok || delay != 5*time.Second {
		t.Fatalf("delay=%v ok=%v, want 5s true", delay, ok)
	}
}

func TestRetryAfterHugeSecondsIsCappedWithoutOverflow(t *testing.T) {
	got, ok := parseRetryAfter("9223372036854775807", time.Now(), 30*time.Second)
	if !ok || got != 30*time.Second {
		t.Fatalf("parseRetryAfter()=(%v,%v), want (30s,true)", got, ok)
	}
}

func TestRetryAfterOutOfRangePositiveSecondsSaturates(t *testing.T) {
	got, ok := parseRetryAfter(strings.Repeat("9", 1000), time.Now(), 30*time.Second)
	if !ok || got != 30*time.Second {
		t.Fatalf("parseRetryAfter()=(%v,%v), want (30s,true)", got, ok)
	}
}

func TestRetryAfterHTTPDate(t *testing.T) {
	now := time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC)
	value := now.Add(3 * time.Second).Format(http.TimeFormat)
	delay, ok := parseRetryAfter(value, now, 10*time.Second)
	if !ok || delay != 3*time.Second {
		t.Fatalf("delay=%v ok=%v, want 3s true", delay, ok)
	}
}

func TestCancellationInterruptsBackoff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "later", http.StatusTooManyRequests)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	policy := DefaultPolicy("test.cancel", Idempotent)
	policy.RetryAfterCap = 30 * time.Second
	done := make(chan error, 1)
	go func() {
		_, err := Do(ctx, server.Client(), policy, func(ctx context.Context, _ int) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodPut, server.URL, nil)
		}, nil)
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt retry wait")
	}
}

func TestRetryAttemptsAreGloballyCapped(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("temporary transport failure")
	})}
	policy := DefaultPolicy("test.bounded", Idempotent)
	policy.MaxAttempts = 20
	policy.BaseDelay = time.Nanosecond
	policy.MaxDelay = time.Nanosecond
	_, err := Do(context.Background(), client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, "https://example.test/bounded", nil)
	}, nil)
	if err == nil {
		t.Fatal("Do() error=nil, want bounded retry exhaustion")
	}
	if got := calls.Load(); got != 8 {
		t.Fatalf("calls=%d, want global cap of 8", got)
	}
}

func TestDoRebindsRequestToAuthorityContext(t *testing.T) {
	client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-time.After(200 * time.Millisecond):
			return nil, errors.New("request context was not rebound")
		}
	})}
	ctx, cancel := context.WithCancel(context.Background())
	policy := DefaultPolicy("test.context", SingleAttempt)
	done := make(chan error, 1)
	go func() {
		_, err := Do(ctx, client, policy, func(_ context.Context, _ int) (*http.Request, error) {
			// Deliberately ignore the authority-supplied context. Do must still bind
			// the outbound request to ctx so cancellation cannot be bypassed by a
			// buggy request factory.
			return http.NewRequest(http.MethodPost, "https://example.test/context", nil)
		}, nil)
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Do did not honor authority context cancellation")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func discardBodyResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}
}

func TestExecutorSharesRateLimitCooldownPerAction(t *testing.T) {
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	exec := NewExecutor(8)
	exec.now = func() time.Time { return now }
	var waits []time.Duration
	exec.waitFn = func(ctx context.Context, delay time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		waits = append(waits, delay)
		now = now.Add(delay)
		return nil
	}

	var aCalls atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/a":
			if aCalls.Add(1) == 1 {
				resp := discardBodyResponse(http.StatusTooManyRequests)
				resp.Header.Set("Retry-After", "1")
				return resp, nil
			}
			return discardBodyResponse(http.StatusOK), nil
		case "/b":
			return discardBodyResponse(http.StatusOK), nil
		default:
			return discardBodyResponse(http.StatusNotFound), nil
		}
	})}

	policyA := DefaultPolicy("provider.a.update", SingleAttempt)
	outcome, err := exec.Do(context.Background(), client, policyA, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, "https://example.test/a", nil)
	}, nil)
	if err != nil {
		t.Fatalf("first A Do() error=%v", err)
	}
	if outcome.Response == nil || outcome.Response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("first A response=%v, want 429", outcome.Response)
	}
	outcome.Response.Body.Close()

	// An unrelated action must not inherit A's provider cooldown.
	policyB := DefaultPolicy("provider.b.update", SingleAttempt)
	outcome, err = exec.Do(context.Background(), client, policyB, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, "https://example.test/b", nil)
	}, nil)
	if err != nil {
		t.Fatalf("B Do() error=%v", err)
	}
	outcome.Response.Body.Close()
	if len(waits) != 0 {
		t.Fatalf("unrelated action waited: %v", waits)
	}

	// The next A call is automatically held until the shared Retry-After window.
	outcome, err = exec.Do(context.Background(), client, policyA, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, "https://example.test/a", nil)
	}, nil)
	if err != nil {
		t.Fatalf("second A Do() error=%v", err)
	}
	outcome.Response.Body.Close()
	if len(waits) != 1 || waits[0] != time.Second {
		t.Fatalf("cooldown waits=%v, want [1s]", waits)
	}
	stats := exec.Stats()
	if stats.RateLimits != 1 || stats.CooldownWaits != 1 {
		t.Fatalf("stats=%+v, want one rate limit and one cooldown wait", stats)
	}
}

func TestExecutorCooldownStateIsBounded(t *testing.T) {
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	exec := NewExecutor(2)
	exec.now = func() time.Time { return now }
	exec.waitFn = func(ctx context.Context, delay time.Duration) error {
		now = now.Add(delay)
		return ctx.Err()
	}
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		resp := discardBodyResponse(http.StatusTooManyRequests)
		resp.Header.Set("Retry-After", "30")
		return resp, nil
	})}

	for _, action := range []string{"provider.a", "provider.b", "provider.c"} {
		policy := DefaultPolicy(action, SingleAttempt)
		outcome, err := exec.Do(context.Background(), client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/mutate", nil)
		}, nil)
		if err != nil {
			t.Fatalf("%s Do() error=%v", action, err)
		}
		outcome.Response.Body.Close()
	}
	if got := exec.Stats().CooldownKeys; got != 2 {
		t.Fatalf("cooldown keys=%d, want hard cap 2", got)
	}
}

func TestExecutorCooldownWaitHonorsCancellationBeforeRequest(t *testing.T) {
	exec := NewExecutor(4)
	exec.rememberCooldown("provider.cancel", time.Now().Add(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return discardBodyResponse(http.StatusOK), nil
	})}
	policy := DefaultPolicy("provider.cancel", SingleAttempt)
	_, err := exec.Do(ctx, client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/mutate", nil)
	}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context canceled", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("requests=%d, want zero while canceled cooldown is pending", calls.Load())
	}
}

func TestExecutorSharesCooldownAcrossActionsInSameProviderScope(t *testing.T) {
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	exec := NewExecutor(8)
	exec.now = func() time.Time { return now }
	exec.jitterFn = func(delay time.Duration) time.Duration { return delay }
	var waits []time.Duration
	exec.waitFn = func(ctx context.Context, delay time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		waits = append(waits, delay)
		now = now.Add(delay)
		return nil
	}

	var first atomic.Bool
	client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/dns" && !first.Swap(true) {
			resp := discardBodyResponse(http.StatusTooManyRequests)
			resp.Header.Set("Retry-After", "2")
			return resp, nil
		}
		return discardBodyResponse(http.StatusOK), nil
	})}

	firstPolicy := DefaultPolicy("cloudflare.dns.update", SingleAttempt)
	firstPolicy.RateLimitScope = "provider.cloudflare"
	outcome, err := exec.Do(context.Background(), client, firstPolicy, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, "https://example.test/dns", nil)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome.Response.Body.Close()

	secondPolicy := DefaultPolicy("cloudflare.worker.upload", SingleAttempt)
	secondPolicy.RateLimitScope = "provider.cloudflare"
	outcome, err = exec.Do(context.Background(), client, secondPolicy, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, "https://example.test/worker", nil)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome.Response.Body.Close()
	if len(waits) != 1 || waits[0] != 2*time.Second {
		t.Fatalf("waits=%v, want shared provider cooldown of 2s", waits)
	}
}

func TestExecutorProviderScopesRemainIsolated(t *testing.T) {
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	exec := NewExecutor(8)
	exec.now = func() time.Time { return now }
	exec.jitterFn = func(delay time.Duration) time.Duration { return delay }
	var waits []time.Duration
	exec.waitFn = func(ctx context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		now = now.Add(delay)
		return ctx.Err()
	}
	client := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/cloudflare" {
			resp := discardBodyResponse(http.StatusTooManyRequests)
			resp.Header.Set("Retry-After", "3")
			return resp, nil
		}
		return discardBodyResponse(http.StatusOK), nil
	})}

	cloudflare := DefaultPolicy("cloudflare.dns.update", SingleAttempt)
	cloudflare.RateLimitScope = "provider.cloudflare"
	outcome, err := exec.Do(context.Background(), client, cloudflare, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, "https://example.test/cloudflare", nil)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome.Response.Body.Close()

	google := DefaultPolicy("gdrive.file.upload", SingleAttempt)
	google.RateLimitScope = "provider.google-drive"
	outcome, err = exec.Do(context.Background(), client, google, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/google", nil)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome.Response.Body.Close()
	if len(waits) != 0 {
		t.Fatalf("unrelated provider inherited cooldown: %v", waits)
	}
}

func TestExecutorBoundsConcurrentMutationsPerScope(t *testing.T) {
	exec := NewExecutor(8)
	started := make(chan struct{}, 3)
	releaseRequests := make(chan struct{})
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-releaseRequests
		return discardBodyResponse(http.StatusOK), nil
	})}
	policy := DefaultPolicy("cloudflare.concurrent", SingleAttempt)
	policy.RateLimitScope = "provider.cloudflare"
	policy.MaxInFlight = 2

	done := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			outcome, err := exec.Do(context.Background(), client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
				return http.NewRequestWithContext(ctx, http.MethodPut, "https://example.test/mutate", nil)
			}, nil)
			if outcome.Response != nil {
				outcome.Response.Body.Close()
			}
			done <- err
		}()
	}

	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("expected first two in-flight requests")
		}
	}
	select {
	case <-started:
		t.Fatal("third request bypassed per-scope in-flight bound")
	case <-time.After(30 * time.Millisecond):
	}

	releaseRequests <- struct{}{}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("third request did not start after capacity was released")
	}
	releaseRequests <- struct{}{}
	releaseRequests <- struct{}{}
	for i := 0; i < 3; i++ {
		if err := <-done; err != nil {
			t.Fatalf("Do() error=%v", err)
		}
	}
	if stats := exec.Stats(); stats.InFlightWaits == 0 || stats.InFlight != 0 || stats.ActiveScopes != 0 {
		t.Fatalf("stats=%+v, want a bounded wait and no leaked in-flight state", stats)
	}
}

func TestExecutorFailsClosedWhenActiveScopeCapacityIsExhausted(t *testing.T) {
	exec := NewExecutor(1)
	entered := make(chan struct{})
	unblock := make(chan struct{})
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		close(entered)
		<-unblock
		return discardBodyResponse(http.StatusOK), nil
	})}
	first := DefaultPolicy("provider.a.action", SingleAttempt)
	first.RateLimitScope = "provider.a"
	done := make(chan error, 1)
	go func() {
		outcome, err := exec.Do(context.Background(), client, first, func(ctx context.Context, _ int) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/a", nil)
		}, nil)
		if outcome.Response != nil {
			outcome.Response.Body.Close()
		}
		done <- err
	}()
	<-entered

	second := DefaultPolicy("provider.b.action", SingleAttempt)
	second.RateLimitScope = "provider.b"
	_, err := exec.Do(context.Background(), client, second, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, "https://example.test/b", nil)
	}, nil)
	if !errors.Is(err, ErrCoordinatorCapacity) {
		t.Fatalf("error=%v, want ErrCoordinatorCapacity", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("requests=%d, want no second-provider side effect", calls.Load())
	}
	close(unblock)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if exec.Stats().CapacityStops != 1 {
		t.Fatalf("stats=%+v, want one capacity stop", exec.Stats())
	}
}

func TestExecutorJittersOnlyLocalBackoff(t *testing.T) {
	exec := NewExecutor(8)
	exec.jitterFn = func(delay time.Duration) time.Duration {
		if delay != 100*time.Millisecond {
			t.Fatalf("jitter input=%v, want 100ms", delay)
		}
		return 63 * time.Millisecond
	}
	var waits []time.Duration
	exec.waitFn = func(ctx context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		return ctx.Err()
	}
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("temporary transport failure")
		}
		return discardBodyResponse(http.StatusOK), nil
	})}
	policy := DefaultPolicy("test.jitter", Idempotent)
	policy.BaseDelay = 100 * time.Millisecond
	policy.MaxDelay = 100 * time.Millisecond
	outcome, err := exec.Do(context.Background(), client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, "https://example.test/jitter", nil)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome.Response.Body.Close()
	if len(waits) != 1 || waits[0] != 63*time.Millisecond {
		t.Fatalf("waits=%v, want jittered local backoff", waits)
	}
}

func TestRetryAfterRemainsProviderAuthoritativeWithoutJitter(t *testing.T) {
	now := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	exec := NewExecutor(8)
	exec.now = func() time.Time { return now }
	exec.jitterFn = func(time.Duration) time.Duration { return time.Nanosecond }
	var waits []time.Duration
	exec.waitFn = func(ctx context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		now = now.Add(delay)
		return ctx.Err()
	}
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			resp := discardBodyResponse(http.StatusServiceUnavailable)
			resp.Header.Set("Retry-After", "2")
			return resp, nil
		}
		return discardBodyResponse(http.StatusOK), nil
	})}
	policy := DefaultPolicy("provider.authoritative", Idempotent)
	outcome, err := exec.Do(context.Background(), client, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPut, "https://example.test/retry-after", nil)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome.Response.Body.Close()
	if len(waits) != 1 || waits[0] != 2*time.Second {
		t.Fatalf("waits=%v, want exact provider Retry-After", waits)
	}
}
