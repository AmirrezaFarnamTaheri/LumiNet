// Copyright 2024 LumiNet. Use of this source code is governed by the MIT license.

// Package dns implements domain name resolution strategies and load-balancing algorithms
// compatible with the dnscrypt-proxy LBStrategy interface.
// LBStrategy defines the contract for selecting an upstream among a pool, while the
// concrete implementations provide weighted-random, round-robin, and power-of-2-latency
// selection strategies.

package dns

import (
	"math"
	"math/rand"
	"sync"
)

// Upstream describes a single upstream server with enough metadata for LB decisions.
type Upstream struct {
	ID       string  // Unique identifier, e.g. "cloudflare-1"
	Name     string  // Display name, e.g. "Cloudflare 1.1.1.1"
	Addr     string  // Network address, e.g. "1.1.1.1:853"
	Weight   float64 // Relative weight for weighted strategies (0 = excluded)
	Latency  float64 // Most recent RTT in milliseconds; updated externally.
	Failures int     // Consecutive query failures; reset on success.
}

// LBStrategy selects an upstream from a pool. Implementations are safe for
// concurrent use.
type LBStrategy interface {
	// Select returns the index of the chosen upstream in the pool slice.
	// Returns -1 when the pool is empty.
	Select(pool []Upstream) int
	// RecordSuccess updates internal state after a successful query to upstream at idx.
	RecordSuccess(idx int)
	// RecordFailure updates internal state after a failed query to upstream at idx.
	RecordFailure(idx int)
	// Name returns the strategy identifier, matching the dnscrypt-proxy config key.
	Name() string
}

// LBStrategyConfig holds parameters for strategy construction.
type LBStrategyConfig struct {
	// Strategy selects which strategy to instantiate.
	// Accepted values: "random", "weighted", "round_robin", "p2".
	Strategy string
	// FailPenalty is added to the failure counter each time RecordFailure is called.
	// A higher value makes a strategy de-prioritise unhealthy upstreams faster.
	FailPenalty float64
	// P2SampleSize is the number of random upstreams considered by the P2 strategy.
	P2SampleSize int
}

// NewLBStrategy constructs the strategy requested by cfg. When cfg.Strategy is empty
// or unknown, NewLBStrategy returns a weighted strategy as the sensible default.
func NewLBStrategy(cfg LBStrategyConfig) LBStrategy {
	switch cfg.Strategy {
	case "random":
		return &randomStrategy{}
	case "round_robin":
		return &roundRobinStrategy{}
	case "p2":
		sampleSize := cfg.P2SampleSize
		if sampleSize < 2 {
			sampleSize = 2
		}
		return &p2Strategy{
			sampleSize:  sampleSize,
			failPenalty: cfg.FailPenalty,
		}
	case "weighted", "":
		return newWeightedStrategy(cfg.FailPenalty)
	default:
		return newWeightedStrategy(cfg.FailPenalty)
	}
}

// ---------------------------------------------------------------------------
// Weighted strategy
// ---------------------------------------------------------------------------

type weightedStrategy struct {
	failPenalty float64
}

func newWeightedStrategy(failPenalty float64) *weightedStrategy {
	return &weightedStrategy{failPenalty: failPenalty}
}

// Select implements LBStrategy using weighted random selection. Upstreams with
// weight ≤ 0 are skipped. The effective weight of each upstream is reduced
// proportional to its consecutive failure count, implementing automatic de-prioritisation.
func (s *weightedStrategy) Select(pool []Upstream) int {
	if len(pool) == 0 {
		return -1
	}
	// Build a snapshot of eligible weights.
	type entry struct {
		idx     int
		effWeight float64
	}
	var entries []entry
	for i, u := range pool {
		if u.Weight <= 0 {
			continue
		}
		penalty := s.failPenalty * float64(u.Failures)
		eff := math.Max(0, u.Weight-penalty)
		if eff > 0 {
			entries = append(entries, entry{idx: i, effWeight: eff})
		}
	}
	if len(entries) == 0 {
		// Fallback: pick randomly from the full pool.
		return rand.Intn(len(pool))
	}
	total := 0.0
	for _, e := range entries {
		total += e.effWeight
	}
	threshold := rand.Float64() * total
	cumulative := 0.0
	for _, e := range entries {
		cumulative += e.effWeight
		if threshold < cumulative {
			return e.idx
		}
	}
	return entries[len(entries)-1].idx
}

func (s *weightedStrategy) RecordSuccess(idx int) { /* state lives on the Upstream struct */ }
func (s *weightedStrategy) RecordFailure(idx int) {
	// State is tracked externally in Upstream.Failures; this method is a no-op
	// to satisfy the interface while allowing future in-strategy bookkeeping.
}

func (s *weightedStrategy) Name() string { return "weighted" }

// ---------------------------------------------------------------------------
// Round-robin strategy
// ---------------------------------------------------------------------------

type roundRobinStrategy struct {
	mu     sync.Mutex
	cursor uint64 // atomic-ish index; protected by mutex for simplicity.
}

// Select implements LBStrategy using strict round-robin rotation. Upstreams with
// weight ≤ 0 are skipped without advancing the cursor.
func (s *roundRobinStrategy) Select(pool []Upstream) int {
	if len(pool) == 0 {
		return -1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Advance cursor past ineligible upstreams.
	start := int(s.cursor)
	for i := 0; i < len(pool); i++ {
		idx := (start + i) % len(pool)
		if pool[idx].Weight > 0 {
			s.cursor = uint64(idx + 1)
			return idx
		}
	}
	return -1 // all excluded
}

func (s *roundRobinStrategy) RecordSuccess(idx int) {}
func (s *roundRobinStrategy) RecordFailure(idx int) {}

func (s *roundRobinStrategy) Name() string { return "round_robin" }

// ---------------------------------------------------------------------------
// P2 (power-of-2-choices) strategy
// ---------------------------------------------------------------------------

type p2Strategy struct {
	sampleSize  int
	failPenalty float64
}

// Select implements LBStrategy using the power-of-2-choices algorithm.
// Two upstreams are sampled at random; the one with the lower latency estimate
// is returned. Failure penalties are subtracted from latency to de-prioritise
// unhealthy candidates.
func (s *p2Strategy) Select(pool []Upstream) int {
	n := len(pool)
	if n == 0 {
		return -1
	}
	if n == 1 {
		return 0
	}
	k := s.sampleSize
	if k > n {
		k = n
	}
	var bestIdx int
	bestScore := math.MaxFloat64
	for _, idx := range rand.Perm(n)[:k] {
		u := pool[idx]
		// Treat unknown latency (0) as very large.
		lat := u.Latency
		if lat <= 0 {
			lat = math.MaxFloat64 / 2
		}
		// Penalise failures.
		score := lat + s.failPenalty*float64(u.Failures)*100
		if score < bestScore {
			bestScore = score
			bestIdx = idx
		}
	}
	return bestIdx
}

func (s *p2Strategy) RecordSuccess(idx int) {}
func (s *p2Strategy) RecordFailure(idx int) {}

func (s *p2Strategy) Name() string { return "p2" }

// ---------------------------------------------------------------------------
// Random (baseline) strategy
// ---------------------------------------------------------------------------

type randomStrategy struct{}

func (s *randomStrategy) Select(pool []Upstream) int {
	if len(pool) == 0 {
		return -1
	}
	return rand.Intn(len(pool))
}
func (s *randomStrategy) RecordSuccess(idx int) {}
func (s *randomStrategy) RecordFailure(idx int) {}
func (s *randomStrategy) Name() string         { return "random" }
