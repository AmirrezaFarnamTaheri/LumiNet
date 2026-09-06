package diagnostics

import (
	"reflect"
	"testing"
	"time"
)

func TestBuildEndpointPoolPlan(t *testing.T) {
	now := time.Now()
	p, err := BuildEndpointPoolPlan([]EndpointPoolObservation{
		{Endpoint: "fast", Successes: 10, LatencyMs: 30, RemainingQuota: 900, QuotaLimit: 1000, LastSucceeded: now},
		{Endpoint: "flaky", Successes: 8, Failures: 8, LatencyMs: 100, RemainingQuota: 800, QuotaLimit: 1000, LastFailed: now},
		{Endpoint: "empty", Successes: 10, LatencyMs: 10, QuotaLimit: 1000, RemainingQuota: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.DispatchOrder) != 2 || p.DispatchOrder[0] != "fast" {
		t.Fatalf("plan=%+v", p)
	}
	if p.PreferredEndpoint != "fast" {
		t.Fatalf("preferred endpoint=%q, want fast", p.PreferredEndpoint)
	}
	if p.Ranked[len(p.Ranked)-1].Endpoint != "empty" {
		t.Fatalf("quota exhausted not last: %+v", p.Ranked)
	}
	if !reflect.DeepEqual(p.SelectionBasis, []string{"observed-success", "latency", "quota", "recent-failure"}) {
		t.Fatalf("selection basis=%v", p.SelectionBasis)
	}
}

func TestBuildEndpointPoolPlanRejectsDuplicateAndInvalidQuota(t *testing.T) {
	if _, err := BuildEndpointPoolPlan([]EndpointPoolObservation{{Endpoint: "a"}, {Endpoint: "a"}}); err == nil {
		t.Fatal("expected duplicate endpoint rejection")
	}
	if _, err := BuildEndpointPoolPlan([]EndpointPoolObservation{{Endpoint: "a", RemainingQuota: 2, QuotaLimit: 1}}); err == nil {
		t.Fatal("expected invalid quota rejection")
	}
	for name, observation := range map[string]EndpointPoolObservation{
		"negative jitter": {Endpoint: "a", JitterMs: -1},
		"huge jitter":     {Endpoint: "a", JitterMs: 120001},
		"negative loss":   {Endpoint: "a", PacketLossPct: -0.1},
		"loss over 100":   {Endpoint: "a", PacketLossPct: 100.1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildEndpointPoolPlan([]EndpointPoolObservation{observation}); err == nil {
				t.Fatalf("expected rejection for %+v", observation)
			}
		})
	}
}

func TestBuildEndpointPoolPlanDoesNotDispatchUnobservedOrNeverSuccessfulEndpoints(t *testing.T) {
	p, err := BuildEndpointPoolPlan([]EndpointPoolObservation{
		{Endpoint: "unknown"},
		{Endpoint: "failed-only", Failures: 3, LastFailed: time.Now()},
		{Endpoint: "proven", Successes: 1, Failures: 2, LatencyMs: 120, LastSucceeded: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.DispatchOrder) != 1 || p.DispatchOrder[0] != "proven" {
		t.Fatalf("dispatch order = %v, want only proven endpoint", p.DispatchOrder)
	}
	if p.Ranked[0].Endpoint != "proven" || !p.Ranked[0].Eligible {
		t.Fatalf("proven endpoint not ranked eligible: %+v", p.Ranked)
	}
	for _, rank := range p.Ranked {
		if (rank.Endpoint == "unknown" || rank.Endpoint == "failed-only") && rank.Eligible {
			t.Fatalf("unproven endpoint unexpectedly eligible: %+v", rank)
		}
	}
}

func TestEndpointPoolJitterAndLossOnlyPenalize(t *testing.T) {
	clean := EndpointPoolObservation{Endpoint: "clean", Successes: 20, LatencyMs: 80}
	unstable := EndpointPoolObservation{Endpoint: "unstable", Successes: 20, LatencyMs: 80, JitterMs: 600, PacketLossPct: 25}
	plan, err := BuildEndpointPoolPlan([]EndpointPoolObservation{unstable, clean})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Ranked[0].Endpoint != "clean" || plan.Ranked[0].Score <= plan.Ranked[1].Score {
		t.Fatalf("unexpected quality ranking: %+v", plan.Ranked)
	}
	if !reflect.DeepEqual(plan.SelectionBasis, []string{"observed-success", "latency", "quota", "recent-failure", "jitter", "packet-loss"}) {
		t.Fatalf("selection basis=%v", plan.SelectionBasis)
	}
}

func TestEndpointPoolScopeDiversifiesOnlyNearEquivalentBands(t *testing.T) {
	items := []EndpointPoolObservation{
		{Endpoint: "a", Successes: 10, LatencyMs: 100},
		{Endpoint: "b", Successes: 10, LatencyMs: 120},
		{Endpoint: "materially-worse", Successes: 3, Failures: 7, LatencyMs: 2500},
	}
	first, err := BuildEndpointPoolPlanWithOptions(items, EndpointPoolOptions{Scope: "profile-one"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildEndpointPoolPlanWithOptions(items, EndpointPoolOptions{Scope: "profile-one"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.DispatchOrder, second.DispatchOrder) {
		t.Fatalf("same scope must be deterministic: %v != %v", first.DispatchOrder, second.DispatchOrder)
	}
	if first.DispatchOrder[len(first.DispatchOrder)-1] != "materially-worse" {
		t.Fatalf("diversity crossed quality band: %v", first.DispatchOrder)
	}
	if !first.DiversityApplied {
		t.Fatal("expected diversity_applied")
	}
}

func TestEndpointPoolPreviousSuccessIsHintNotEligibilityBypass(t *testing.T) {
	items := []EndpointPoolObservation{
		{Endpoint: "best", Successes: 10, LatencyMs: 20},
		{Endpoint: "last-good", Successes: 10, Failures: 1, LatencyMs: 20},
		{Endpoint: "disabled", Successes: 10, LatencyMs: 10, Disabled: true},
	}
	plan, err := BuildEndpointPoolPlanWithOptions(items, EndpointPoolOptions{PreviousSuccessful: "last-good"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DispatchOrder[0] != "last-good" || !plan.ReusedPreviousSuccess {
		t.Fatalf("last-known-good not reused: %+v", plan)
	}

	blocked, err := BuildEndpointPoolPlanWithOptions(items, EndpointPoolOptions{PreviousSuccessful: "disabled"})
	if err != nil {
		t.Fatal(err)
	}
	if blocked.ReusedPreviousSuccess || blocked.DispatchOrder[0] == "disabled" {
		t.Fatalf("ineligible previous success bypassed admission: %+v", blocked)
	}
}

func TestEndpointPoolPreviousSuccessCannotOverrideMaterialQualityGap(t *testing.T) {
	items := []EndpointPoolObservation{
		{Endpoint: "best", Successes: 20, LatencyMs: 20},
		{Endpoint: "stale-last-good", Successes: 2, Failures: 8, LatencyMs: 2500},
	}
	plan, err := BuildEndpointPoolPlanWithOptions(items, EndpointPoolOptions{PreviousSuccessful: "stale-last-good"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DispatchOrder[0] != "best" || plan.ReusedPreviousSuccess {
		t.Fatalf("materially worse last-known-good overrode current evidence: %+v", plan)
	}
}

func TestPostRefactor224EndpointHealthCircuitAndCapacityAdmission(t *testing.T) {
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	items := []EndpointPoolObservation{
		{Endpoint: "healthy", Successes: 10, LatencyMs: 50, HealthState: "healthy", Capacity: 10, InFlight: 2},
		{Endpoint: "unhealthy", Successes: 10, LatencyMs: 10, HealthState: "unhealthy"},
		{Endpoint: "circuit", Successes: 10, LatencyMs: 10, ConsecutiveFailures: 3, CooldownUntil: now.Add(time.Minute)},
		{Endpoint: "full", Successes: 10, LatencyMs: 10, Capacity: 2, InFlight: 2},
		{Endpoint: "recovered", Successes: 10, LatencyMs: 60, ConsecutiveFailures: 3, CooldownUntil: now.Add(-time.Minute)},
	}
	plan, err := BuildEndpointPoolPlanWithOptions(items, EndpointPoolOptions{AsOf: now})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.DispatchOrder, []string{"healthy", "recovered"}) {
		t.Fatalf("dispatch order=%v", plan.DispatchOrder)
	}
	byName := map[string]EndpointPoolRank{}
	for _, rank := range plan.Ranked {
		byName[rank.Endpoint] = rank
	}
	if byName["unhealthy"].Eligible || byName["circuit"].Eligible || byName["full"].Eligible {
		t.Fatalf("admission failure: %+v", byName)
	}
	if !byName["circuit"].CircuitOpen || byName["recovered"].CircuitOpen {
		t.Fatalf("cooldown semantics wrong: %+v", byName)
	}
}

func TestPostRefactor224SecondaryStrategiesCannotCrossQualityBand(t *testing.T) {
	items := []EndpointPoolObservation{
		{Endpoint: "best", Successes: 20, LatencyMs: 20, Capacity: 10, InFlight: 9, Weight: 1},
		{Endpoint: "near", Successes: 20, LatencyMs: 100, Capacity: 10, InFlight: 1, Weight: 10},
		{Endpoint: "materially-worse", Successes: 4, Failures: 6, LatencyMs: 2500, Capacity: 10, InFlight: 0, Weight: 100},
	}
	for _, strategy := range []string{"least-loaded", "weighted-quality"} {
		plan, err := BuildEndpointPoolPlanWithOptions(items, EndpointPoolOptions{Strategy: strategy})
		if err != nil {
			t.Fatal(err)
		}
		if plan.DispatchOrder[len(plan.DispatchOrder)-1] != "materially-worse" {
			t.Fatalf("%s crossed material quality band: %v", strategy, plan.DispatchOrder)
		}
	}
}

func TestPostRefactor224StickyCannotPromoteMateriallyWorseEndpoint(t *testing.T) {
	items := []EndpointPoolObservation{
		{Endpoint: "best", Successes: 20, LatencyMs: 20},
		{Endpoint: "materially-worse", Successes: 2, Failures: 8, LatencyMs: 2500},
	}
	plan, err := BuildEndpointPoolPlanWithOptions(items, EndpointPoolOptions{Strategy: "sticky", PreviousSuccessful: "materially-worse"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DispatchOrder[0] != "best" || plan.ReusedPreviousSuccess {
		t.Fatalf("sticky hint crossed material quality band: %+v", plan)
	}
}

func TestPostRefactor229QuotaSafetyBufferReservesHeadroom(t *testing.T) {
	reset := time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC)
	plan, err := BuildEndpointPoolPlan([]EndpointPoolObservation{
		{Endpoint: "safe", Successes: 10, RemainingQuota: 700, QuotaLimit: 1000, QuotaSafetyBuffer: 500, QuotaResetAt: reset},
		{Endpoint: "reserved", Successes: 10, RemainingQuota: 500, QuotaLimit: 1000, QuotaSafetyBuffer: 500, QuotaResetAt: reset},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.DispatchOrder, []string{"safe"}) {
		t.Fatalf("dispatch order=%v", plan.DispatchOrder)
	}
	byName := map[string]EndpointPoolRank{}
	for _, rank := range plan.Ranked {
		byName[rank.Endpoint] = rank
	}
	if byName["safe"].QuotaHeadroom != 200 || byName["safe"].QuotaHeadroomPct != 20 || byName["safe"].QuotaGuarded {
		t.Fatalf("safe headroom=%+v", byName["safe"])
	}
	if !byName["reserved"].QuotaGuarded || byName["reserved"].Eligible || byName["reserved"].Quality != "quota-guarded" {
		t.Fatalf("reserve barrier failed: %+v", byName["reserved"])
	}
	if !reflect.DeepEqual(plan.SelectionBasis, []string{"observed-success", "latency", "quota", "recent-failure", "quota-safety-buffer", "quota-reset-evidence"}) {
		t.Fatalf("selection basis=%v", plan.SelectionBasis)
	}
}

func TestPostRefactor229QuotaSafetyBufferRequiresKnownQuotaLimit(t *testing.T) {
	if _, err := BuildEndpointPoolPlan([]EndpointPoolObservation{{Endpoint: "ambiguous", Successes: 1, QuotaSafetyBuffer: 1}}); err == nil {
		t.Fatal("quota safety buffer without quota limit accepted")
	}
	if _, err := BuildEndpointPoolPlan([]EndpointPoolObservation{{Endpoint: "too-large", Successes: 1, RemainingQuota: 5, QuotaLimit: 10, QuotaSafetyBuffer: 11}}); err == nil {
		t.Fatal("quota safety buffer larger than limit accepted")
	}
}
