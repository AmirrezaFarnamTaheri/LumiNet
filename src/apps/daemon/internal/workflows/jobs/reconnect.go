// Reconnect lineage policy for long-running tunnel jobs.
//
// is never retried; an observed drop consumes one attempt; a proven connection
// resets the budget so long-lived sessions keep full recovery capacity after
// days of stable operation.
package jobs

import (
	"sync"
	"time"
)

// ReconnectPolicy governs automatic restart attempts for one tunnel job.
type ReconnectPolicy struct {
	MaxAttempts     int           // attempts available per stable session, default 3
	FallbackAfter   int           // consecutive exhausted hosts before switching, default = MaxAttempts
	Cooldown        time.Duration // delay between attempts, default 2s
}

// Lineage tracks one job's retry state machine.
type ReconnectLineage struct {
	mu         sync.Mutex
	policy     ReconnectPolicy
	attempts   int
	userStop   bool
	everProven bool
	host       string
}

// NewReconnectLineage builds lineage with sane defaults.
func NewReconnectLineage(policy ReconnectPolicy) *ReconnectLineage {
	if policy.MaxAttempts <= 0 {
		policy.MaxAttempts = 3
	}
	if policy.FallbackAfter <= 0 {
		policy.FallbackAfter = policy.MaxAttempts
	}
	if policy.Cooldown <= 0 {
		policy.Cooldown = 2 * time.Second
	}
	return &ReconnectLineage{policy: policy}
}

// OnUserStop records an explicit user request; retries are suppressed until
// the user starts the job again.
func (l *ReconnectLineage) OnUserStop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.userStop = true
	l.attempts = 0
}

// OnStart clears any prior user-stop and arms the lineage for a fresh run.
func (l *ReconnectLineage) OnStart(host string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.userStop = false
	l.attempts = 0
	l.host = host
	if !l.everProven || l.host != "" {
		// new host: full budget regardless of history
		l.everProven = l.everProven && l.host == ""
	}
}

// OnConnected marks the tunnel as proven; the retry budget resets so a drop
// hours later still enjoys the full attempt count.
func (l *ReconnectLineage) OnConnected() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts = 0
	l.everProven = true
}

// OnDrop records an observed disconnect. Returns whether another automatic
// attempt is authorised and how long to wait first.
func (l *ReconnectLineage) OnDrop() (retry bool, cooldown time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.userStop {
		return false, 0
	}
	if l.attempts >= l.policy.MaxAttempts {
		return false, 0
	}
	l.attempts++
	return true, l.policy.Cooldown
}

// CanRetry reports whether attempts remain without consuming one.
func (l *ReconnectLineage) CanRetry() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.userStop && l.attempts < l.policy.MaxAttempts
}

// AttemptsUsed reports consumed attempts in the current lineage.
func (l *ReconnectLineage) AttemptsUsed() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.attempts
}
