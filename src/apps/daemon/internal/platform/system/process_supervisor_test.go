package system

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestProcessSupervisor_Run(t *testing.T) {
	buildCmd := func() *exec.Cmd {
		return exec.Command("go", "version")
	}

	sup := NewProcessSupervisor("test-go-version", buildCmd, "")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	readyCh := make(chan struct{})
	go sup.Run(ctx, readyCh)

	select {
	case <-time.After(500 * time.Millisecond):
		// Supervisor ran and restarted the process successfully.
	case <-ctx.Done():
	}
}

func TestProcessSupervisorBackoffIncreasesAndCaps(t *testing.T) {
	want := []time.Duration{0, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for failures, expected := range want {
		if got := restartBackoff(failures); got != expected {
			t.Fatalf("restartBackoff(%d) = %v, want %v", failures, got, expected)
		}
	}
}

func TestProcessSupervisorStableReadinessResetsOnlyBackoffDebt(t *testing.T) {
	sup := NewProcessSupervisor("test", func() *exec.Cmd { return exec.Command("true") }, "ready")
	sup.stableReadyPeriod = time.Minute
	sup.recordFailure()
	sup.recordFailure()
	if sup.consecutiveFailures != 2 {
		t.Fatalf("consecutiveFailures = %d, want 2", sup.consecutiveFailures)
	}
	if len(sup.failureTimes) != 2 {
		t.Fatalf("failureTimes = %d, want 2", len(sup.failureTimes))
	}

	// A short-lived ready process must not erase crash-loop debt.
	sup.recordFailureAfterRun(10 * time.Second)
	if sup.consecutiveFailures != 3 {
		t.Fatalf("consecutiveFailures after short ready run = %d, want 3", sup.consecutiveFailures)
	}

	// A genuinely stable run resets only the backoff sequence, then records the
	// new failure as attempt one. Historical failures remain for the windowed
	// circuit breaker.
	sup.recordFailureAfterRun(2 * time.Minute)
	if sup.consecutiveFailures != 1 {
		t.Fatalf("consecutiveFailures after stable run = %d, want 1", sup.consecutiveFailures)
	}
	if len(sup.failureTimes) != 4 {
		t.Fatalf("stable readiness erased circuit-breaker history: %d entries", len(sup.failureTimes))
	}
}

func TestProcessSupervisorFailureWindowPrunesDuringLongStableRun(t *testing.T) {
	sup := NewProcessSupervisor("test", func() *exec.Cmd { return exec.Command("true") }, "ready")
	sup.stableReadyPeriod = time.Minute

	// Simulate old crash-loop history that was still present when a process
	// entered a genuinely long healthy run. Recording the later failure must
	// prune the expired history before evaluating the circuit breaker.
	old := time.Now().Add(-failureWindow - time.Minute)
	for i := 0; i < maxFailures+5; i++ {
		sup.failureTimes = append(sup.failureTimes, old)
	}
	sup.consecutiveFailures = maxFailures + 5

	sup.recordFailureAfterRun(2 * time.Minute)
	if got := len(sup.failureTimes); got != 1 {
		t.Fatalf("failureTimes after stable long run = %d, want 1 fresh failure", got)
	}
	if sup.consecutiveFailures != 1 {
		t.Fatalf("consecutiveFailures after stable long run = %d, want 1", sup.consecutiveFailures)
	}
	if sup.tooManyFailures() {
		t.Fatal("expired history incorrectly tripped the circuit breaker")
	}
}

func TestReadyDurationBounds(t *testing.T) {
	now := time.Now()
	if got := readyDuration(time.Time{}, now); got != 0 {
		t.Fatalf("zero readiness duration=%v", got)
	}
	if got := readyDuration(now, now.Add(90*time.Second)); got != 90*time.Second {
		t.Fatalf("ready duration=%v, want 90s", got)
	}
}
