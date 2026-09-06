package relay

import (
	"testing"
	"time"
)

func TestGlobalLimiterStopReleasesBlockedAcquire(t *testing.T) {
	limiter := NewGlobalLimiter(1)
	if limiter == nil {
		t.Fatal("expected limiter")
	}

	if got := limiter.Acquire(minBurst); got != minBurst {
		t.Fatalf("initial grant = %d, want %d", got, minBurst)
	}

	grantCh := make(chan int64, 1)
	go func() {
		grantCh <- limiter.Acquire(1)
	}()

	select {
	case grant := <-grantCh:
		t.Fatalf("Acquire returned before Stop with grant %d", grant)
	case <-time.After(20 * time.Millisecond):
	}

	limiter.Stop()

	select {
	case grant := <-grantCh:
		if grant != 1 {
			t.Fatalf("grant after Stop = %d, want 1", grant)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Acquire remained blocked after Stop")
	}
}

func TestGlobalLimiterAcquireAfterStopIsPassThrough(t *testing.T) {
	limiter := NewGlobalLimiter(1)
	if limiter == nil {
		t.Fatal("expected limiter")
	}
	limiter.Stop()

	const want int64 = 4096
	grantCh := make(chan int64, 1)
	go func() {
		grantCh <- limiter.Acquire(want)
	}()

	select {
	case got := <-grantCh:
		if got != want {
			t.Fatalf("grant after Stop = %d, want %d", got, want)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Acquire blocked after Stop")
	}
}
