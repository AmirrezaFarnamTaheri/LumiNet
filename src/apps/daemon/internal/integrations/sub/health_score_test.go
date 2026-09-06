package sub

import (
	"math"
	"testing"
	"time"
)

func TestHealthScorer_NoSamples(t *testing.T) {
	s := NewHealthScorer()
	score, err := s.ScoreSubscription("missing")
	if err == nil {
		t.Error("expected error for missing subscription")
	}
	if score.SubscriptionID != "" {
		t.Errorf("expected zero score, got %+v", score)
	}
}

func TestHealthScorer_ScoreSubscription_Basics(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s := NewHealthScorer()
	s.SetNow(func() time.Time { return now })

	obs := s.Track("sub-1")
	obs.MaxLatencyMs = 200
	obs.FreshnessWindow = 1 * time.Minute

	for i := 0; i < 5; i++ {
		obs.AddSample(HealthSample{
			LatencyMs: 50,
			Success:   true,
			Timestamp: now.Add(-time.Duration(i) * time.Second),
		})
	}

	score, err := s.ScoreSubscription("sub-1")
	if err != nil {
		t.Fatalf("ScoreSubscription: %v", err)
	}
	if score.SampleSize != 5 {
		t.Errorf("SampleSize: got %d, want 5", score.SampleSize)
	}
	if score.Availability < 0.99 {
		t.Errorf("Availability: got %f, want ~1.0", score.Availability)
	}
	if score.Latency <= 0.5 {
		t.Errorf("Latency: got %f, want >0.5", score.Latency)
	}
	if score.Freshness <= 0.99 {
		t.Errorf("Freshness: got %f, want ~1.0 (latest sample is now)", score.Freshness)
	}
	if score.Total <= 0.5 {
		t.Errorf("Total: got %f, want >0.5", score.Total)
	}
}

func TestHealthScorer_AvailabilityDropsWithFailures(t *testing.T) {
	now := time.Now()
	s := NewHealthScorer()
	s.SetNow(func() time.Time { return now })

	obs := s.Track("sub-2")
	for i := 0; i < 4; i++ {
		obs.AddSample(HealthSample{
			LatencyMs: 10,
			Success:   i%2 == 0,
			Timestamp: now,
		})
	}
	score, _ := s.ScoreSubscription("sub-2")
	if math.Abs(score.Availability-0.5) > 1e-9 {
		t.Errorf("Availability: got %f, want 0.5", score.Availability)
	}
}

func TestHealthScorer_FreshnessDecay(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s := NewHealthScorer()
	s.SetNow(func() time.Time { return now })

	obs := s.Track("sub-3")
	obs.FreshnessWindow = 10 * time.Minute
	obs.AddSample(HealthSample{
		LatencyMs: 100,
		Success:   true,
		Timestamp: now.Add(-5 * time.Minute),
	})
	score, _ := s.ScoreSubscription("sub-3")
	// 5 min old out of 10 min window = 0.5
	if math.Abs(score.Freshness-0.5) > 1e-9 {
		t.Errorf("Freshness: got %f, want 0.5", score.Freshness)
	}
}

func TestHealthScorer_ScoreAllSorted(t *testing.T) {
	now := time.Now()
	s := NewHealthScorer()
	s.SetNow(func() time.Time { return now })

	// A: low latency, all success
	obsA := s.Track("A")
	obsA.AddSample(HealthSample{LatencyMs: 10, Success: true, Timestamp: now})
	// B: high latency, half failure
	obsB := s.Track("B")
	obsB.AddSample(HealthSample{LatencyMs: 500, Success: false, Timestamp: now})
	obsB.AddSample(HealthSample{LatencyMs: 500, Success: true, Timestamp: now})

	scores := s.ScoreAll()
	if len(scores) != 2 {
		t.Fatalf("expected 2 scores, got %d", len(scores))
	}
	if scores[0].SubscriptionID != "A" {
		t.Errorf("A should rank first, got %q", scores[0].SubscriptionID)
	}
}

func TestHealthScorer_Forget(t *testing.T) {
	s := NewHealthScorer()
	s.Track("sub")
	if len(s.TrackedIDs()) != 1 {
		t.Fatalf("expected 1 tracked id, got %d", len(s.TrackedIDs()))
	}
	s.Forget("sub")
	if len(s.TrackedIDs()) != 0 {
		t.Errorf("expected 0 tracked ids after Forget, got %d", len(s.TrackedIDs()))
	}
}

func TestHealthScorer_CustomWeights(t *testing.T) {
	now := time.Now()
	s := NewHealthScorerWithWeights(ScoreWeights{Latency: 1.0, Availability: 0, Freshness: 0})
	s.SetNow(func() time.Time { return now })

	obs := s.Track("sub")
	obs.AddSample(HealthSample{LatencyMs: 100, Success: false, Timestamp: now})
	score, _ := s.ScoreSubscription("sub")
	// Only latency should count, availability is 0 in weights.
	if math.Abs(score.Availability-0) > 1e-9 {
		t.Errorf("Availability weight=0, got %f", score.Availability)
	}
	if score.Total == 0 {
		t.Error("Total should be >0 since latency weight is 1.0")
	}
}

func TestHealthScorer_TrimsToMaxSamples(t *testing.T) {
	s := NewHealthScorer()
	obs := s.Track("sub")
	obs.MaxSamples = 3
	for i := 0; i < 10; i++ {
		obs.AddSample(HealthSample{LatencyMs: i, Success: true, Timestamp: time.Now()})
	}
	if len(obs.Samples) != 3 {
		t.Errorf("expected 3 samples after trim, got %d", len(obs.Samples))
	}
	if obs.Samples[0].LatencyMs != 7 {
		t.Errorf("expected oldest 7, got %d", obs.Samples[0].LatencyMs)
	}
}
