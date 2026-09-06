package trust

import (
	"sync"
	"testing"
	"time"
)

func newTestStore() *Store {
	return &Store{metrics: make(map[string]*Metrics)}
}

func TestUnknownNodeUsesBaselineTrust(t *testing.T) {
	store := newTestStore()
	if got := store.ComputeTrustScore("unknown"); got != 0.8 {
		t.Fatalf("baseline trust = %v, want 0.8", got)
	}
}

func TestMetricsAndRatingsChangeTrustThroughPublicInterface(t *testing.T) {
	store := newTestStore()
	store.RecordMetric("node", 100*time.Millisecond, true, 0.05)
	before := store.ComputeTrustScore("node")
	store.SubmitRating("node", 1.0)
	after := store.ComputeTrustScore("node")
	if before <= 0 || before > 1 {
		t.Fatalf("metric-derived trust = %v, want (0,1]", before)
	}
	if after >= before {
		t.Fatalf("low user rating should reduce trust: before=%v after=%v", before, after)
	}
}

func TestTrustScoreIsClamped(t *testing.T) {
	store := newTestStore()
	for i := 0; i < 20; i++ {
		store.RecordMetric("bad", 2*time.Second, false, 5.0)
	}
	if got := store.ComputeTrustScore("bad"); got != 0 {
		t.Fatalf("negative weighted score must clamp to zero, got %v", got)
	}
}

func TestStoreSupportsConcurrentMetricAndRatingUpdates(t *testing.T) {
	store := newTestStore()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			store.RecordMetric("node", 25*time.Millisecond, true, 0.01)
		}()
		go func() {
			defer wg.Done()
			store.SubmitRating("node", 4.0)
		}()
	}
	wg.Wait()
	if got := store.ComputeTrustScore("node"); got < 0 || got > 1 {
		t.Fatalf("trust score after concurrent updates = %v, want [0,1]", got)
	}
}

func TestSnapshotScoresContainsOnlyObservedNodes(t *testing.T) {
	store := newTestStore()
	if got := store.SnapshotScores(); len(got) != 0 {
		t.Fatalf("empty store snapshot=%v, want no fabricated nodes", got)
	}
	store.RecordMetric("real-node", 25*time.Millisecond, true, 0)
	got := store.SnapshotScores()
	if len(got) != 1 {
		t.Fatalf("snapshot=%v, want one observed node", got)
	}
	if _, ok := got["real-node"]; !ok {
		t.Fatalf("snapshot=%v missing observed node", got)
	}
}
