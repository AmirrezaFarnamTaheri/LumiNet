package system

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestTunnelMonitorStepSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("uag=Mozilla/5.0\n"))
	}))
	defer ts.Close()

	var recoveredCount int32
	recoveryFn := func(ctx context.Context) error {
		atomic.AddInt32(&recoveredCount, 1)
		return nil
	}

	cfg := TunnelMonitorConfig{
		Enabled:          true,
		URL:              ts.URL,
		FailureThreshold: 2,
		Cooldown:         time.Minute,
	}

	monitor := NewTunnelMonitorWithClient(cfg, ts.Client(), recoveryFn, time.Now)
	rec, err := monitor.Step(context.Background())
	if err != nil {
		t.Fatalf("unexpected probe error: %v", err)
	}
	if rec {
		t.Fatalf("did not expect recovery on success")
	}
	if monitor.failures != 0 {
		t.Fatalf("expected failures 0, got %d", monitor.failures)
	}
	if atomic.LoadInt32(&recoveredCount) != 0 {
		t.Fatalf("expected 0 recoveries, got %d", recoveredCount)
	}
}

func TestTunnelMonitorStepFailureAndRecovery(t *testing.T) {
	var statusCode int32 = http.StatusOK
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(atomic.LoadInt32(&statusCode)))
	}))
	defer ts.Close()

	var recoveryCalls int32
	recoveryFn := func(ctx context.Context) error {
		atomic.AddInt32(&recoveryCalls, 1)
		return nil
	}

	fakeNow := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		return fakeNow
	}

	cfg := TunnelMonitorConfig{
		Enabled:          true,
		URL:              ts.URL,
		FailureThreshold: 3,
		Cooldown:         5 * time.Minute,
	}

	monitor := NewTunnelMonitorWithClient(cfg, ts.Client(), recoveryFn, clock)

	// Cause failures
	atomic.StoreInt32(&statusCode, http.StatusBadGateway)

	// Step 1: failure 1
	rec, err := monitor.Step(context.Background())
	if err == nil || rec {
		t.Fatalf("expected failure without recovery, rec=%v, err=%v", rec, err)
	}
	if monitor.failures != 1 {
		t.Fatalf("expected failures=1, got %d", monitor.failures)
	}

	// Step 2: failure 2
	rec, err = monitor.Step(context.Background())
	if err == nil || rec {
		t.Fatalf("expected failure without recovery, rec=%v, err=%v", rec, err)
	}
	if monitor.failures != 2 {
		t.Fatalf("expected failures=2, got %d", monitor.failures)
	}

	// Step 3: failure 3 -> triggers recovery!
	rec, err = monitor.Step(context.Background())
	if err == nil || !rec {
		t.Fatalf("expected recovery on 3rd failure, rec=%v, err=%v", rec, err)
	}
	if atomic.LoadInt32(&recoveryCalls) != 1 {
		t.Fatalf("expected 1 recovery call, got %d", recoveryCalls)
	}
	if monitor.failures != 0 {
		t.Fatalf("expected failures reset to 0 after recovery, got %d", monitor.failures)
	}

	// Step 4: immediate next failure is within cooldown
	rec, err = monitor.Step(context.Background())
	if err == nil || rec {
		t.Fatalf("expected failure without recovery during cooldown, rec=%v, err=%v", rec, err)
	}
	// Failures count is 1
	rec, err = monitor.Step(context.Background()) // 2
	rec, err = monitor.Step(context.Background()) // 3 -> threshold reached, but cooldown active!
	if err == nil || rec {
		t.Fatalf("expected no recovery during cooldown, rec=%v, err=%v", rec, err)
	}
	if atomic.LoadInt32(&recoveryCalls) != 1 {
		t.Fatalf("expected recovery calls still 1 during cooldown, got %d", recoveryCalls)
	}

	// Advance time past cooldown (5 min)
	fakeNow = fakeNow.Add(6 * time.Minute)

	// Step 5: next failure after cooldown should now trigger recovery!
	rec, err = monitor.Step(context.Background())
	if err == nil || !rec {
		t.Fatalf("expected recovery after cooldown expired, rec=%v, err=%v", rec, err)
	}
	if atomic.LoadInt32(&recoveryCalls) != 2 {
		t.Fatalf("expected 2 recovery calls, got %d", recoveryCalls)
	}
}

func TestTunnelMonitorRecoveryError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	recoveryFn := func(ctx context.Context) error {
		return errors.New("reboot failed")
	}

	cfg := TunnelMonitorConfig{
		Enabled:          true,
		URL:              ts.URL,
		FailureThreshold: 1,
		Cooldown:         time.Minute,
	}

	monitor := NewTunnelMonitorWithClient(cfg, ts.Client(), recoveryFn, time.Now)
	rec, err := monitor.Step(context.Background())
	if rec {
		t.Fatalf("rec should be false when recovery handler itself fails")
	}
	if err == nil {
		t.Fatalf("expected error from failed recovery")
	}
}
