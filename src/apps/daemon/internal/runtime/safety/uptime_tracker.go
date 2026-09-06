package safety

import (
	"sync"
	"time"
)

// PingCheckResult stores an individual ping outcome.
type PingCheckResult struct {
	Timestamp time.Time     `json:"timestamp"`
	Success   bool          `json:"success"`
	Latency   time.Duration `json:"latency"`
}

// UptimeTracker maintains a rolling window of probe results and calculates availability.
type UptimeTracker struct {
	mu           sync.Mutex
	history      []PingCheckResult
	maxHistory   int
	totalChecks  int
	failedChecks int
}

// NewUptimeTracker initializes a tracker with a specified history size.
func NewUptimeTracker(maxHistory int) *UptimeTracker {
	if maxHistory <= 0 {
		maxHistory = 100
	}
	return &UptimeTracker{
		maxHistory: maxHistory,
	}
}

// RecordCheck logs a probe result.
func (u *UptimeTracker) RecordCheck(success bool, latency time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.totalChecks++
	if !success {
		u.failedChecks++
	}

	res := PingCheckResult{
		Timestamp: time.Now(),
		Success:   success,
		Latency:   latency,
	}

	u.history = append(u.history, res)
	if len(u.history) > u.maxHistory {
		u.history = u.history[1:]
	}
}

// AvailabilityPercentage computes percentage uptime (0.0 to 100.0).
func (u *UptimeTracker) AvailabilityPercentage() float64 {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.totalChecks == 0 {
		return 100.0
	}
	passed := u.totalChecks - u.failedChecks
	return (float64(passed) / float64(u.totalChecks)) * 100.0
}

// RecentHistory returns a copy of recent checks.
func (u *UptimeTracker) RecentHistory() []PingCheckResult {
	u.mu.Lock()
	defer u.mu.Unlock()
	res := make([]PingCheckResult, len(u.history))
	copy(res, u.history)
	return res
}
