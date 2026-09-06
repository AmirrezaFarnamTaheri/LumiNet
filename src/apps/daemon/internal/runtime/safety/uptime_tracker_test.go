package safety

import (
	"testing"
	"time"
)

func TestUptimeTrackerPercentage(t *testing.T) {
	tracker := NewUptimeTracker(10)

	tracker.RecordCheck(true, 15*time.Millisecond)
	tracker.RecordCheck(true, 18*time.Millisecond)
	tracker.RecordCheck(false, 0)
	tracker.RecordCheck(true, 22*time.Millisecond)

	// 3 successes out of 4 = 75%
	pct := tracker.AvailabilityPercentage()
	if pct != 75.0 {
		t.Errorf("expected 75.0 availability percentage, got %f", pct)
	}

	history := tracker.RecentHistory()
	if len(history) != 4 {
		t.Errorf("expected 4 history items, got %d", len(history))
	}
}
