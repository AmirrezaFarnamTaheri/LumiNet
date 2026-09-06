package scanner

import (
	"testing"
	"time"
)

func TestBuildPlanBoundsLargeCIDRAtSource(t *testing.T) {
	done := make(chan struct{})
	var plan *ScanPlan
	var err error
	go func() {
		defer close(done)
		plan, err = BuildPlan(PlanConfig{CIDRs: []string{"10.0.0.0/8"}, Ports: PortSpec{443}, MaxTargets: 2})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("BuildPlan materialized the large CIDR instead of respecting MaxTargets at the source")
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Targets) != 2 || !plan.Truncated {
		t.Fatalf("plan=%+v", plan)
	}
	if plan.EvaluatedCandidates > 8 {
		t.Fatalf("evaluated %d candidates for two targets", plan.EvaluatedCandidates)
	}
}

func TestBuildPlanNormalizesPortsBeforeBudgeting(t *testing.T) {
	plan, err := BuildPlan(PlanConfig{Hosts: []string{"1.1.1.1", "2.2.2.2"}, Ports: PortSpec{443, 443, 0, 80}, MaxTargets: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Targets) != 3 {
		t.Fatalf("targets=%+v", plan.Targets)
	}
	if plan.Targets[0].Port != 80 || plan.Targets[1].Port != 443 || plan.Targets[2].Port != 80 {
		t.Fatalf("ports were not normalized before target budgeting: %+v", plan.Targets)
	}
}

func TestBuildPlanFromSubnetDivisionIsLazyForHugeIPv6Space(t *testing.T) {
	done := make(chan struct{})
	var plan *ScanPlan
	var err error
	go func() {
		defer close(done)
		plan, err = BuildPlanFromSubnetDivision("2001:db8::/32", 64, PlanConfig{Ports: PortSpec{443}, MaxTargets: 2})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("subnet division attempted to enumerate the full /32 -> /64 space")
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Targets) != 2 || !plan.Truncated {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestBuildPlanCandidateCeilingBoundsExcludedUniverse(t *testing.T) {
	plan, err := BuildPlan(PlanConfig{
		CIDRs:        []string{"10.0.0.0/8"},
		ExcludeCIDRs: []string{"10.0.0.0/9"},
		Ports:        PortSpec{443}, MaxTargets: 2, MaxCandidates: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.CandidateLimitReached || plan.EvaluatedCandidates != 32 {
		t.Fatalf("candidate ceiling not visible: %+v", plan)
	}
	if len(plan.Targets) != 0 {
		t.Fatalf("unexpected targets before exclusion ceiling: %+v", plan.Targets)
	}
}
