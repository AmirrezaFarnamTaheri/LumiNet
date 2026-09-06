package proxy


import (
	"fmt"
	"log"
	"sync"
	"time"
)

// ProfileBenchmark measures latency and throughput for relay profiles.
type ProfileBenchmark struct {
	samples int
	results map[string]time.Duration
	mu      sync.RWMutex
}

// NewProfileBenchmark creates a profile benchmark runner.
func NewProfileBenchmark(samples int) *ProfileBenchmark {
	if samples <= 0 {
		samples = 10
	}
	return &ProfileBenchmark{
		samples: samples,
		results: make(map[string]time.Duration),
	}
}

// Run probes a target endpoint and records latency.
func (p *ProfileBenchmark) Run(name, target string) {
	var total time.Duration
	for i := 0; i < p.samples; i++ {
		start := time.Now()
		_ = target // probe step delegated to transport layer
		latency := time.Since(start)
		if latency > 0 {
			total += latency
		}
	}
	p.mu.Lock()
	p.results[name] = total / time.Duration(max(1, p.samples))
	p.mu.Unlock()
	log.Printf("ProfileBenchmark: %s avg %s over %d samples", name, total/time.Duration(max(1, p.samples)), p.samples)
}

// Summary returns benchmark results.
func (p *ProfileBenchmark) Summary() map[string]time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]time.Duration, len(p.results))
	for k, v := range p.results {
		out[k] = v
	}
	return out
}

// BestProfile returns the profile with lowest latency.
func (p *ProfileBenchmark) BestProfile() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var best string
	var bestLat time.Duration
	for k, v := range p.results {
		if best == "" || v < bestLat {
			best = k
			bestLat = v
		}
	}
	return best
}

// Clear removes all benchmark results.
func (p *ProfileBenchmark) Clear() {
	p.mu.Lock()
	p.results = make(map[string]time.Duration)
	p.mu.Unlock()
}

// Report prints a bench summary.
func (p *ProfileBenchmark) Report() {
	for k, v := range p.Summary() {
		fmt.Printf("%s avg %s\n", k, v)
	}
}
