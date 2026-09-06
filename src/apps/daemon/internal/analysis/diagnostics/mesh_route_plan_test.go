package diagnostics

import (
	"testing"
	"time"
)

func b(v bool) *bool { return &v }
func TestBuildMeshRoutePlanPolicies(t *testing.T) {
	req := MeshRouteRequest{Source: "a", Nodes: []string{"a", "b", "c"}, Edges: []MeshRouteEdge{{From: "a", To: "b", LatencyMs: 50}, {From: "b", To: "c", LatencyMs: 50}, {From: "a", To: "c", LatencyMs: 120, LossPct: 10}}}
	p, err := BuildMeshRoutePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	var c MeshRoute
	for _, r := range p.Routes {
		if r.Destination == "c" {
			c = r
		}
	}
	if c.NextHop != "b" || c.Hops != 2 {
		t.Fatalf("latency-first route=%+v", c)
	}
	req.Policy = "least-hop"
	p, err = BuildMeshRoutePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Routes {
		if r.Destination == "c" {
			c = r
		}
	}
	if c.NextHop != "c" || c.Hops != 1 {
		t.Fatalf("least-hop route=%+v", c)
	}
	req.Edges[2].Active = b(false)
	p, err = BuildMeshRoutePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Routes {
		if r.Destination == "c" {
			c = r
		}
	}
	if c.Hops != 2 {
		t.Fatalf("inactive edge used: %+v", c)
	}
}

func TestBuildMeshRoutePlanRejectsBadGraph(t *testing.T) {
	if _, err := BuildMeshRoutePlan(MeshRouteRequest{Source: "a", Nodes: []string{"a", "a"}}); err == nil {
		t.Fatal("expected duplicate node rejection")
	}
	if _, err := BuildMeshRoutePlan(MeshRouteRequest{Source: "a", Nodes: []string{"a", "b"}, Edges: []MeshRouteEdge{{From: "a", To: "b", LatencyMs: 1, LossPct: 101}}}); err == nil {
		t.Fatal("expected loss bound rejection")
	}
}

func TestPostRefactor224MeshHealthStalenessAndDegradedPenalty(t *testing.T) {
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	req := MeshRouteRequest{
		Source: "a", Nodes: []string{"a", "b", "c", "d"}, AsOf: now, StaleAfterSeconds: 60,
		Edges: []MeshRouteEdge{
			{From: "a", To: "b", LatencyMs: 20, HealthState: "healthy", ObservedAt: now.Add(-time.Second)},
			{From: "b", To: "c", LatencyMs: 20, HealthState: "healthy", ObservedAt: now.Add(-time.Second)},
			{From: "a", To: "c", LatencyMs: 10, HealthState: "unhealthy", ObservedAt: now},
			{From: "a", To: "d", LatencyMs: 10, HealthState: "healthy", ObservedAt: now.Add(-2 * time.Minute)},
			{From: "b", To: "d", LatencyMs: 30, HealthState: "degraded", ObservedAt: now},
		},
	}
	plan, err := BuildMeshRoutePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	byDest := map[string]MeshRoute{}
	for _, r := range plan.Routes {
		byDest[r.Destination] = r
	}
	if byDest["c"].NextHop != "b" {
		t.Fatalf("unhealthy direct edge was used: %+v", byDest["c"])
	}
	if byDest["d"].NextHop != "b" {
		t.Fatalf("stale direct edge was used: %+v", byDest["d"])
	}
	if byDest["d"].Cost <= 30 {
		t.Fatalf("degraded edge was not penalized: %+v", byDest["d"])
	}
}

func TestPostRefactor224MeshTypedHealthEvidenceIsBounded(t *testing.T) {
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	_, err := BuildMeshRoutePlan(MeshRouteRequest{
		Source: "a", Nodes: []string{"a", "b"}, AsOf: now,
		Edges: []MeshRouteEdge{{From: "a", To: "b", LatencyMs: 10, HealthState: "excellent", ObservedAt: now}},
	})
	if err == nil {
		t.Fatal("expected unknown health vocabulary rejection")
	}
	plan, err := BuildMeshRoutePlan(MeshRouteRequest{
		Source: "a", Nodes: []string{"a", "b"}, AsOf: now, StaleAfterSeconds: 60,
		Edges: []MeshRouteEdge{{From: "a", To: "b", LatencyMs: 10, HealthState: "degraded", ObservedAt: now}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Routes) != 1 || plan.Routes[0].Destination != "b" || plan.Routes[0].Cost <= 10 {
		t.Fatalf("degraded evidence was not retained as bounded negative evidence: %+v", plan)
	}
}
