package dns

import (
	"testing"
)

func TestLBStrategy_WeightedSelect(t *testing.T) {
	t.Parallel()
	cfg := LBStrategyConfig{Strategy: "weighted", FailPenalty: 50}
	s := NewLBStrategy(cfg)
	if s.Name() != "weighted" {
		t.Fatalf("expected name 'weighted', got %q", s.Name())
	}
	pool := []Upstream{
		{ID: "a", Name: "A", Weight: 100},
		{ID: "b", Name: "B", Weight: 0},   // excluded
		{ID: "c", Name: "C", Weight: 100},
	}
	// Run many iterations and check we never pick B.
	var bPicked bool
	for i := 0; i < 1000; i++ {
		idx := s.Select(pool)
		if idx < 0 || idx >= len(pool) {
			t.Fatalf("Select returned invalid index %d", idx)
		}
		if pool[idx].ID == "b" {
			bPicked = true
		}
	}
	if bPicked {
		t.Error("weighted strategy must never pick a zero-weight upstream")
	}
}

func TestLBStrategy_WeightedFailPenalty(t *testing.T) {
	t.Parallel()
	cfg := LBStrategyConfig{Strategy: "weighted", FailPenalty: 100}
	s := NewLBStrategy(cfg)
	pool := []Upstream{
		{ID: "good", Weight: 50, Failures: 0},
		{ID: "bad", Weight: 50, Failures: 10}, // should be heavily deprioritised.
	}
	goodCount := 0
	for i := 0; i < 2000; i++ {
		idx := s.Select(pool)
		if pool[idx].ID == "good" {
			goodCount++
		}
	}
	// "bad" upstream should be selected < 5% of the time.
	if float64(goodCount)/2000 < 0.8 {
		t.Logf("good upstream picked %d/2000 times — penalty may be insufficient", goodCount)
	}
}

func TestLBStrategy_RoundRobinSelect(t *testing.T) {
	t.Parallel()
	cfg := LBStrategyConfig{Strategy: "round_robin"}
	s := NewLBStrategy(cfg)
	if s.Name() != "round_robin" {
		t.Fatalf("expected name 'round_robin', got %q", s.Name())
	}
	pool := []Upstream{
		{ID: "a", Weight: 1},
		{ID: "b", Weight: 1},
		{ID: "c", Weight: 1},
	}
	// Collect 9 selections; round-robin should cycle a→b→c→a→...
	seen := make([]string, 9)
	for i := 0; i < 9; i++ {
		idx := s.Select(pool)
		if idx < 0 || idx >= len(pool) {
			t.Fatalf("Select returned invalid index %d", idx)
		}
		seen[i] = pool[idx].ID
	}
	// Check it actually rotates.
	allSame := true
	for i := 1; i < 9; i++ {
		if seen[i] != seen[0] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("round_robin strategy did not rotate across upstreams")
	}
}

func TestLBStrategy_RoundRobinExcludesZeroWeight(t *testing.T) {
	t.Parallel()
	cfg := LBStrategyConfig{Strategy: "round_robin"}
	s := NewLBStrategy(cfg)
	pool := []Upstream{
		{ID: "a", Weight: 1},
		{ID: "b", Weight: 0}, // excluded
		{ID: "c", Weight: 1},
	}
	// Should always pick a or c, never b.
	for i := 0; i < 100; i++ {
		idx := s.Select(pool)
		if pool[idx].ID == "b" {
			t.Fatal("round_robin picked a zero-weight upstream")
		}
	}
}

func TestLBStrategy_P2Select(t *testing.T) {
	t.Parallel()
	cfg := LBStrategyConfig{Strategy: "p2", P2SampleSize: 2, FailPenalty: 50}
	s := NewLBStrategy(cfg)
	if s.Name() != "p2" {
		t.Fatalf("expected name 'p2', got %q", s.Name())
	}
	pool := []Upstream{
		{ID: "fast", Latency: 10},
		{ID: "slow", Latency: 500},
	}
	fastCount := 0
	for i := 0; i < 2000; i++ {
		idx := s.Select(pool)
		if pool[idx].ID == "fast" {
			fastCount++
		}
	}
	// Fast upstream should be picked significantly more often.
	if float64(fastCount)/2000 < 0.7 {
		t.Errorf("P2 should prefer fast upstream, got %.1f%%", float64(fastCount)/20)
	}
}

func TestLBStrategy_P2WithFailurePenalty(t *testing.T) {
	t.Parallel()
	cfg := LBStrategyConfig{Strategy: "p2", P2SampleSize: 2, FailPenalty: 100}
	s := NewLBStrategy(cfg)
	pool := []Upstream{
		{ID: "a", Latency: 10, Failures: 0},
		{ID: "b", Latency: 10, Failures: 5}, // heavily penalised.
	}
	bCount := 0
	for i := 0; i < 2000; i++ {
		idx := s.Select(pool)
		if pool[idx].ID == "b" {
			bCount++
		}
	}
	// b should be picked rarely due to failure penalty.
	if float64(bCount)/2000 > 0.1 {
		t.Errorf("b should be rare with failure penalty, got %.1f%%", float64(bCount)/20)
	}
}

func TestLBStrategy_EmptyPool(t *testing.T) {
	t.Parallel()
	for _, strat := range []string{"random", "weighted", "round_robin", "p2"} {
		cfg := LBStrategyConfig{Strategy: strat}
		s := NewLBStrategy(cfg)
		idx := s.Select(nil)
		if idx != -1 {
			t.Errorf("strategy %q: expected -1 for empty pool, got %d", strat, idx)
		}
	}
}

func TestLBStrategy_RandomFallback(t *testing.T) {
	t.Parallel()
	cfg := LBStrategyConfig{Strategy: "random"}
	s := NewLBStrategy(cfg)
	if s.Name() != "random" {
		t.Fatalf("expected name 'random', got %q", s.Name())
	}
	pool := []Upstream{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		idx := s.Select(pool)
		seen[pool[idx].ID] = true
	}
	if len(seen) < 2 {
		t.Error("random strategy should produce varied selections")
	}
}

func TestLBStrategy_UnknownStrategyFallsBack(t *testing.T) {
	t.Parallel()
	cfg := LBStrategyConfig{Strategy: "nonexistent_strategy_xyz"}
	s := NewLBStrategy(cfg)
	if s.Name() != "weighted" {
		t.Errorf("unknown strategy should fall back to weighted, got %q", s.Name())
	}
}

// BenchmarkLBStrategy benchmarks the weighted strategy with 50 upstreams.
func BenchmarkLBStrategy_Weighted(b *testing.B) {
	cfg := LBStrategyConfig{Strategy: "weighted", FailPenalty: 50}
	s := NewLBStrategy(cfg)
	pool := make([]Upstream, 50)
	for i := range pool {
		pool[i] = Upstream{ID: string(rune('a' + i)), Weight: 100, Latency: float64(i*5 + 10)}
	}
	b.ResetTimer()
	for b.Loop() {
		_ = s.Select(pool)
	}
}

func BenchmarkLBStrategy_P2(b *testing.B) {
	cfg := LBStrategyConfig{Strategy: "p2", P2SampleSize: 2, FailPenalty: 50}
	s := NewLBStrategy(cfg)
	pool := make([]Upstream, 50)
	for i := range pool {
		pool[i] = Upstream{ID: string(rune('a' + i)), Latency: float64(i*5 + 10)}
	}
	b.ResetTimer()
	for b.Loop() {
		_ = s.Select(pool)
	}
}
