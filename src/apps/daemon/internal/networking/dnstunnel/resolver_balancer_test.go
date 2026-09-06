package dnstunnel

import (
	"testing"
)

func tieredPlans() []ResolverPlan {
	return []ResolverPlan{
		{Name: "fast-clean", Tier: "active", LossPct: 0.1, RTTMs: 20, EffectiveGoodputKbps: 9000},
		{Name: "lossy", Tier: "active", LossPct: 12.0, RTTMs: 30, EffectiveGoodputKbps: 800},
		{Name: "slow-clean", Tier: "reserve", LossPct: 0.2, RTTMs: 180, EffectiveGoodputKbps: 4000},
		{Name: "broken", Tier: "invalid", LossPct: 100, RTTMs: 0},
	}
}

func TestNewBalancerFiltersInvalidTier(t *testing.T) {
	b, err := NewBalancer(BalanceRoundRobin, tieredPlans(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Len() != 3 {
		t.Fatalf("eligible = %d, want 3 (invalid filtered)", b.Len())
	}
}

func TestNewBalancerRejectsUnknownModeAndEmptySet(t *testing.T) {
	if _, err := NewBalancer("mystery-mode", tieredPlans(), 0); err == nil {
		t.Fatal("unknown mode accepted")
	}
	broken := []ResolverPlan{{Name: "dead", Tier: "invalid"}}
	if _, err := NewBalancer(BalanceRoundRobin, broken, 0); err == nil {
		t.Fatal("empty eligible set accepted")
	}
}

func TestLeastLossPicksCleanest(t *testing.T) {
	b, _ := NewBalancer(BalanceLeastLoss, tieredPlans(), 0)
	for range 20 {
		idx := b.Pick()
		if got := b.Plan(idx).Name; got != "fast-clean" {
			t.Fatalf("least-loss picked %q", got)
		}
	}
}

func TestLowestLatencyPicksFastestRTT(t *testing.T) {
	b, _ := NewBalancer(BalanceLowestLatency, tieredPlans(), 0)
	for range 20 {
		if got := b.Plan(b.Pick()).Name; got != "fast-clean" {
			t.Fatalf("lowest-latency picked %q", got)
		}
	}
}

func TestLossThenLatencyPrefersLossFirst(t *testing.T) {
	plans := []ResolverPlan{
		{Name: "low-loss-slow", Tier: "active", LossPct: 0.0, RTTMs: 300},
		{Name: "high-loss-fast", Tier: "active", LossPct: 5.0, RTTMs: 5},
	}
	b, _ := NewBalancer(BalanceLossThenLatency, plans, 0)
	for range 15 {
		if got := b.Plan(b.Pick()).Name; got != "low-loss-slow" {
			t.Fatalf("loss-then-latency picked %q", got)
		}
	}
}

func TestRoundRobinCycles(t *testing.T) {
	b, _ := NewBalancer(BalanceRoundRobin, tieredPlans(), 0)
	first := b.Pick()
	second := b.Pick()
	third := b.Pick()
	fourth := b.Pick()
	if first == second || second == third {
		t.Fatalf("round-robin repeated consecutive picks: %d %d %d", first, second, third)
	}
	if fourth != first {
		t.Fatalf("cycle did not wrap: first=%d fourth=%d", first, fourth)
	}
}

func TestTopNRandomStaysWithinN(t *testing.T) {
	b, _ := NewBalancer(BalanceTopNRandom, tieredPlans(), 1)
	// top-N=1 over loss-sorted plans → always index 0 ("fast-clean")
	for range 30 {
		if got := b.Plan(b.Pick()).Name; got != "fast-clean" {
			t.Fatalf("top-N=1 leaked outside: %q", got)
		}
	}
}

func TestHybridScoreBalancesLossAndLatency(t *testing.T) {
	b, _ := NewBalancer(BalanceHybridScore, tieredPlans(), 0)
	picked := map[string]int{}
	for range 50 {
		picked[b.Plan(b.Pick()).Name]++
	}
	if len(picked) != 1 {
		t.Fatalf("hybrid-score should be deterministic here, saw %v", picked)
	}
}
