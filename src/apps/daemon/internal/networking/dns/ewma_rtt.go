// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.
// Exponentially-weighted moving average RTT tracking for DNS upstreams.
// Ported (clean room) from RFC 6298-style EWMA, the original Unix TCP retransmit
// estimator. Suitable for tracking per-upstream RTT in DNS load-balancing and
// racing strategies.

package dns

import (
	"sync"
	"time"
)

// EWMARtt tracks the smoothed RTT for a single upstream.
// All methods are safe for concurrent use.
type EWMARtt struct {
	mu         sync.Mutex
	alpha      float64       // smoothing factor in (0, 1].
	smoothedRTT time.Duration // current estimate.
	rttVar      time.Duration // RTT variance (RFC 6298 RTTVAR).
	initialized bool
	lastObserved time.Time
}

// NewEWMARtt constructs a tracker with the given smoothing factor alpha.
// alpha = 0.125 mirrors the RFC 6298 RTO estimator (the standard TCP alpha).
func NewEWMARtt(alpha float64) *EWMARtt {
	if alpha <= 0 || alpha > 1 {
		alpha = 0.125
	}
	return &EWMARtt{alpha: alpha}
}

// Observe records a new RTT sample.
// First sample seeds both SRTT and RTTVAR; subsequent samples are smoothed.
func (e *EWMARtt) Observe(rtt time.Duration) {
	if rtt < 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lastObserved = time.Now()
	if !e.initialized {
		e.smoothedRTT = rtt
		e.rttVar = rtt / 2
		e.initialized = true
		return
	}
	// RFC 6298 §2.2 update rules.
	// err = |SRTT - R'|
	// SRTT = (1 - alpha) * SRTT + alpha * R'
	// RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|, beta = 0.25
	err := e.smoothedRTT - rtt
	if err < 0 {
		err = -err
	}
	beta := 0.25
	e.rttVar = time.Duration((1-beta)*float64(e.rttVar) + beta*float64(err))
	e.smoothedRTT = time.Duration((1-e.alpha)*float64(e.smoothedRTT) + e.alpha*float64(rtt))
}

// Smoothed returns the current EWMA RTT estimate. Returns 0 when no sample has
// been observed yet.
func (e *EWMARtt) Smoothed() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.smoothedRTT
}

// RTO returns the RFC 6298 retransmission timeout estimate: SRTT + max(G, 4 * RTTVAR).
// K = 4, G is the clock granularity (1 ms in practice).
func (e *EWMARtt) RTO() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.initialized {
		return 0
	}
	g := time.Millisecond
	variance := 4 * e.rttVar
	if variance < g {
		variance = g
	}
	return e.smoothedRTT + variance
}

// Reset forgets all observations.
func (e *EWMARtt) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.smoothedRTT = 0
	e.rttVar = 0
	e.initialized = false
}

// Initialized reports whether at least one sample has been observed.
func (e *EWMARtt) Initialized() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.initialized
}

// EWMARttRegistry holds a per-upstream EWMARtt tracker keyed by upstream ID.
type EWMARttRegistry struct {
	mu       sync.RWMutex
	alpha    float64
	trackers map[string]*EWMARtt
}

// NewEWMARttRegistry constructs a registry with the given smoothing factor.
func NewEWMARttRegistry(alpha float64) *EWMARttRegistry {
	if alpha <= 0 || alpha > 1 {
		alpha = 0.125
	}
	return &EWMARttRegistry{
		alpha:    alpha,
		trackers: make(map[string]*EWMARtt),
	}
}

// For returns the tracker for upstreamID, creating it on first access.
func (r *EWMARttRegistry) For(upstreamID string) *EWMARtt {
	r.mu.RLock()
	t, ok := r.trackers[upstreamID]
	r.mu.RUnlock()
	if ok {
		return t
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok = r.trackers[upstreamID]; ok {
		return t
	}
	t = NewEWMARtt(r.alpha)
	r.trackers[upstreamID] = t
	return t
}

// Forget removes a tracker.
func (r *EWMARttRegistry) Forget(upstreamID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.trackers, upstreamID)
}

// IDs returns the set of currently tracked upstream IDs.
func (r *EWMARttRegistry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.trackers))
	for id := range r.trackers {
		out = append(out, id)
	}
	return out
}
