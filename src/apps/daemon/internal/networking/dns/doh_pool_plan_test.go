package dns

import (
	"reflect"
	"testing"
	"time"
)

func TestPostRefactor224ResolverPoolAdmissionCircuitsAndOrdering(t *testing.T) {
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	plan, err := BuildResolverPoolPlan(ResolverPoolPlanRequest{AsOf: now, MaxFallbacks: 4, Candidates: []ResolverPoolCandidate{
		{ID: "active-fast", URL: "https://one.example/dns-query", BootstrapIPs: []string{"1.1.1.1"}, Priority: 10, RTTMs: 20, CanaryStatus: "pass"},
		{ID: "active-slow", URL: "https://two.example/dns-query", Priority: 10, RTTMs: 50, CanaryStatus: "pass"},
		{ID: "unknown", URL: "https://three.example/dns-query", Priority: 1, CanaryStatus: "unknown"},
		{ID: "circuit", URL: "https://four.example/dns-query", Priority: 1, CanaryStatus: "pass", ConsecutiveFailures: 3, CooldownUntil: now.Add(time.Minute)},
		{ID: "bad-bootstrap", URL: "https://five.example/dns-query", BootstrapIPs: []string{"not-an-ip"}, CanaryStatus: "pass"},
		{ID: "credential", URL: "https://user:pass@six.example/dns-query", CanaryStatus: "pass"},
		{ID: "plaintext", URL: "http://seven.example/dns-query", CanaryStatus: "pass"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ReadOnly {
		t.Fatal("resolver planner must remain read-only")
	}
	if got := []string{plan.Active[0].ID, plan.Active[1].ID}; !reflect.DeepEqual(got, []string{"active-fast", "active-slow"}) {
		t.Fatalf("active order=%v", got)
	}
	if len(plan.Reserve) != 2 || len(plan.Invalid) != 3 {
		t.Fatalf("tiers active=%d reserve=%d invalid=%d", len(plan.Active), len(plan.Reserve), len(plan.Invalid))
	}
	if !reflect.DeepEqual(plan.FallbackOrder, []string{"active-fast", "active-slow", "circuit", "unknown"}) {
		t.Fatalf("fallback=%v", plan.FallbackOrder)
	}
}

func TestPostRefactor224Quad9VariantsRemainDistinctPresets(t *testing.T) {
	seen := map[string]string{}
	for _, p := range ResolverPoolPresets() {
		seen[p.ID] = p.URL
	}
	for _, id := range []string{"quad9-secured", "quad9-unsecured", "quad9-secured-ecs"} {
		if seen[id] == "" {
			t.Fatalf("missing %s", id)
		}
	}
	if seen["quad9-secured"] == seen["quad9-unsecured"] || seen["quad9-secured"] == seen["quad9-secured-ecs"] || seen["quad9-unsecured"] == seen["quad9-secured-ecs"] {
		t.Fatalf("quad9 variants collapsed: %+v", seen)
	}
}
