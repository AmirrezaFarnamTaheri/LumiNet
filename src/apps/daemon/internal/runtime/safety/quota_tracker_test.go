package safety

import (
	"testing"
	"time"
)

func TestTokenBucketLimiter(t *testing.T) {
	limiter := NewTokenBucketLimiter(10, 5) // 10 tokens/sec, capacity 5

	// Consume capacity
	for i := 0; i < 5; i++ {
		if !limiter.Allow() {
			t.Fatalf("expected token %d to be allowed", i)
		}
	}

	// 6th immediately should fail
	if limiter.Allow() {
		t.Fatalf("expected 6th immediate token to be rejected")
	}

	// Wait for refill
	time.Sleep(250 * time.Millisecond)
	if !limiter.Allow() {
		t.Fatalf("expected token to be available after refill")
	}
}

func TestMultiQuotaTracker(t *testing.T) {
	tracker := NewMultiQuotaTracker(10, 3) // 10s window, 3 requests max
	tracker.Register("acc1")
	tracker.Register("acc2")

	now := int64(1000)
	tracker.RecordOutcome("acc1", now, 100, 100, true)
	tracker.RecordOutcome("acc1", now+1, 100, 100, true)
	tracker.RecordOutcome("acc1", now+2, 100, 100, true)

	// acc1 should now be exhausted
	best, ok := tracker.SelectBestAccount(now + 3)
	if !ok {
		t.Fatalf("expected account to be available")
	}
	if best != "acc2" {
		t.Fatalf("expected acc2 to be selected, got %s", best)
	}

	// Quota rollover after window
	bestRollover, ok := tracker.SelectBestAccount(now + 15)
	if !ok {
		t.Fatalf("expected account available after window reset")
	}
	if bestRollover == "" {
		t.Fatalf("expected valid account after reset")
	}
}
