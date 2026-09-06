// Package system provides platform and system orchestration routines for LumiNet.
//
// Maintains the client's guard set and enforces the rotation policy
// described in prop 247 / arti `guardmgr`: keep a small set of long-lived
// guards, fall back to the next one when the primary has been idle past
// the rotation interval. Avoids the churn-and-correlate attack where a
// client that picks a new guard every circuit makes itself trivially
// observable.

package system

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// Guard is a Tor entry relay used as a persistent first hop.
type Guard struct {
	Fingerprint string
	Nickname    string
	Address     string
	ORPort      int
	AddedAt     time.Time
	LastUsed    time.Time
}

// GuardRotationPolicy bounds the guard set size and the primary's idle
// window. Defaults: 3 guards, 30 days between rotations — matches
// arti's `Guard` config defaults.
type GuardRotationPolicy struct {
	MaxGuards        int
	RotationInterval time.Duration
}

// DefaultGuardRotationPolicy returns arti's recommended 3 / 30-day window.
func DefaultGuardRotationPolicy() GuardRotationPolicy {
	return GuardRotationPolicy{MaxGuards: 3, RotationInterval: 30 * 24 * time.Hour}
}

// GuardManager owns an ordered guard list and a primary pointer.
//
// ponytail: a single primary idx is fine for the single-process case; for
// concurrent guard selection across goroutines you'll want a per-circuit
// view (arti `GuardView`) — add it when stream throughput justifies.
type GuardManager struct {
	mu         sync.RWMutex
	guards     []*Guard
	policy     GuardRotationPolicy
	primaryIdx int
}

// NewGuardManager builds a manager with `policy`. Zero-value policy
// falls back to DefaultGuardRotationPolicy.
func NewGuardManager(policy GuardRotationPolicy) *GuardManager {
	if policy.MaxGuards <= 0 || policy.RotationInterval <= 0 {
		policy = DefaultGuardRotationPolicy()
	}
	return &GuardManager{policy: policy}
}

// Add enrolls a new guard. Errors when the addition would exceed MaxGuards
// or when a guard with the same fingerprint is already enrolled. Stamps
// AddedAt=now when zero.
func (g *GuardManager) Add(guard Guard) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if guard.Fingerprint == "" {
		return errors.New("guard_manager: fingerprint required")
	}
	for _, ex := range g.guards {
		if ex.Fingerprint == guard.Fingerprint {
			return fmt.Errorf("guard_manager: duplicate guard %s", guard.Fingerprint)
		}
	}
	if len(g.guards) >= g.policy.MaxGuards {
		return fmt.Errorf("guard_manager: at capacity %d", g.policy.MaxGuards)
	}
	if guard.AddedAt.IsZero() {
		guard.AddedAt = time.Now()
	}
	g.guards = append(g.guards, &guard)
	return nil
}

// Primary returns the active primary guard, or nil when the set is empty.
func (g *GuardManager) Primary() *Guard {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if len(g.guards) == 0 {
		return nil
	}
	if g.primaryIdx >= len(g.guards) {
		g.primaryIdx = 0
	}
	return g.guards[g.primaryIdx]
}

// Rotate advances the primary pointer by one slot (wrap-around). Errors
// when fewer than two guards are enrolled.
func (g *GuardManager) Rotate() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.guards) < 2 {
		return errors.New("guard_manager: <2 guards enrolled")
	}
	g.primaryIdx = (g.primaryIdx + 1) % len(g.guards)
	return nil
}

// NeedsRotation reports whether the primary guard's LastUsed predates
// `now - RotationInterval`. When the guard list is empty or LastUsed is
// zero, returns false (nothing to rotate, or never used).
func (g *GuardManager) NeedsRotation() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if len(g.guards) == 0 || g.primaryIdx >= len(g.guards) {
		return false
	}
	primary := g.guards[g.primaryIdx]
	if primary.LastUsed.IsZero() {
		return false
	}
	return time.Since(primary.LastUsed) > g.policy.RotationInterval
}

// MarkUsed stamps the primary's LastUsed to now.
func (g *GuardManager) MarkUsed() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.guards) == 0 || g.primaryIdx >= len(g.guards) {
		return
	}
	g.guards[g.primaryIdx].LastUsed = time.Now()
}

// List returns a defensive copy of the guard set.
func (g *GuardManager) List() []Guard {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Guard, 0, len(g.guards))
	for _, gp := range g.guards {
		out = append(out, *gp)
	}
	return out
}
