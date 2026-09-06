// Package sub implements subscription management for proxy services. This
// file implements the health-scoring subsystem
// ConfigRotator module. The scoring is clean-room: no code is copied.
package sub

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// HealthScore is a per-subscription evaluation result. Values are normalised
// to the [0, 1] range for composability.
type HealthScore struct {
	SubscriptionID string
	Latency       float64
	Availability  float64
	Freshness     float64
	Total         float64
	SampleSize    int
	LastEvaluated time.Time
}

// ScoreWeights configures the relative importance of each component.
// They must sum to 1.0 for normalised output.
type ScoreWeights struct {
	Latency      float64
	Availability float64
	Freshness    float64
}

var DefaultScoreWeights = ScoreWeights{Latency: 0.4, Availability: 0.4, Freshness: 0.2}
var EqualScoreWeights = ScoreWeights{Latency: 1.0 / 3.0, Availability: 1.0 / 3.0, Freshness: 1.0 / 3.0}

// HealthSample is a single measurement.
type HealthSample struct {
	SubscriptionID string
	LatencyMs     int
	Success       bool
	Timestamp     time.Time
}

// HealthObservation aggregates samples for one subscription.
type HealthObservation struct {
	SubscriptionID  string
	Samples        []HealthSample
	MaxSamples     int
	MaxLatencyMs   int
	FreshnessWindow time.Duration
}

func NewHealthObservation(id string) *HealthObservation {
	return &HealthObservation{
		SubscriptionID:  id,
		MaxSamples:      32,
		MaxLatencyMs:   1000,
		FreshnessWindow: 10 * time.Minute,
	}
}

func (h *HealthObservation) AddSample(s HealthSample) {
	if h.SubscriptionID == "" {
		h.SubscriptionID = s.SubscriptionID
	}
	s.SubscriptionID = h.SubscriptionID
	h.Samples = append(h.Samples, s)
	if len(h.Samples) > h.MaxSamples {
		h.Samples = h.Samples[len(h.Samples)-h.MaxSamples:]
	}
}

// HealthScorer tracks multiple HealthObservations and produces HealthScores.
type HealthScorer struct {
	mu      sync.RWMutex
	obs     map[string]*HealthObservation
	weights ScoreWeights
	now     func() time.Time
}

func NewHealthScorer() *HealthScorer {
	return &HealthScorer{
		obs:     make(map[string]*HealthObservation),
		weights: DefaultScoreWeights,
		now:     time.Now,
	}
}

func NewHealthScorerWithWeights(w ScoreWeights) *HealthScorer {
	s := NewHealthScorer()
	s.weights = w
	return s
}

func (s *HealthScorer) SetWeights(w ScoreWeights) {
	s.mu.Lock()
	s.weights = w
	s.mu.Unlock()
}

func (s *HealthScorer) Track(id string) *HealthObservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if obs, ok := s.obs[id]; ok {
		return obs
	}
	obs := NewHealthObservation(id)
	s.obs[id] = obs
	return obs
}

func (s *HealthScorer) Forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.obs, id)
}

func (s *HealthScorer) AddSample(sample HealthSample) {
	obs := s.Track(sample.SubscriptionID)
	obs.AddSample(sample)
}

func (s *HealthScorer) ScoreSubscription(id string) (HealthScore, error) {
	s.mu.RLock()
	obs, ok := s.obs[id]
	weights := s.weights
	now := s.now()
	s.mu.RUnlock()

	if !ok {
		return HealthScore{}, fmt.Errorf("health: unknown subscription %q", id)
	}
	if len(obs.Samples) == 0 {
		return HealthScore{SubscriptionID: id, Total: 0, LastEvaluated: now}, nil
	}

	latency := scoreLatency(obs.Samples, obs.MaxLatencyMs)
	avail := scoreAvailability(obs.Samples)
	fresh := scoreFreshness(obs.Samples, obs.FreshnessWindow, now)
	total := latency*weights.Latency + avail*weights.Availability + fresh*weights.Freshness

	return HealthScore{
		SubscriptionID: id,
		Latency:       clamp01(latency),
		Availability:  clamp01(avail),
		Freshness:     clamp01(fresh),
		Total:         clamp01(total),
		SampleSize:    len(obs.Samples),
		LastEvaluated: now,
	}, nil
}

func (s *HealthScorer) ScoreAll() []HealthScore {
	s.mu.RLock()
	ids := make([]string, 0, len(s.obs))
	for id := range s.obs {
		ids = append(ids, id)
	}
	s.mu.RUnlock()

	scores := make([]HealthScore, 0, len(ids))
	for _, id := range ids {
		score, err := s.ScoreSubscription(id)
		if err != nil {
			continue
		}
		scores = append(scores, score)
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].Total != scores[j].Total {
			return scores[i].Total > scores[j].Total
		}
		return scores[i].SubscriptionID < scores[j].SubscriptionID
	})
	return scores
}

func (s *HealthScorer) TrackedIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.obs))
	for id := range s.obs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *HealthScorer) SetNow(fn func() time.Time) {
	s.mu.Lock()
	s.now = fn
	s.mu.Unlock()
}

func scoreLatency(samples []HealthSample, maxMs int) float64 {
	if maxMs <= 0 {
		maxMs = 1000
	}
	var sum, count int
	for _, s := range samples {
		if s.LatencyMs < 0 {
			continue
		}
		sum += s.LatencyMs
		count++
	}
	if count == 0 {
		return 0
	}
	avg := float64(sum) / float64(count)
	if avg > float64(maxMs) {
		return 0
	}
	return 1.0 - avg/float64(maxMs)
}

func scoreAvailability(samples []HealthSample) float64 {
	if len(samples) == 0 {
		return 0
	}
	ok := 0
	for _, s := range samples {
		if s.Success {
			ok++
		}
	}
	return float64(ok) / float64(len(samples))
}

func scoreFreshness(samples []HealthSample, window time.Duration, now time.Time) float64 {
	if window <= 0 {
		window = 10 * time.Minute
	}
	if len(samples) == 0 {
		return 0
	}
	// Samples may arrive out of chronological order (e.g. replayed
	// feeds); "latest" is the max timestamp, not the last element.
	latest := samples[0].Timestamp
	for _, smp := range samples[1:] {
		if smp.Timestamp.After(latest) {
			latest = smp.Timestamp
		}
	}
	age := now.Sub(latest)
	if age <= 0 {
		return 1
	}
	if age >= window {
		return 0
	}
	return 1.0 - float64(age)/float64(window)
}

func clamp01(v float64) float64 {
	if math.IsNaN(v) {
		return 0
	}
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
