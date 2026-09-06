package diagnostics

import (
	"reflect"
	"strings"
	"testing"
)

func TestPostRefactor232MultipathRoundRobinAndAuthority(t *testing.T) {
	plan, err := BuildMultipathTransportPlan(MultipathTransportPlanRequest{
		Algorithm: "round-robin", PreviewPackets: 6,
		Paths: []MultipathPathObservation{
			{ID: "b", Transport: "webtunnel", Healthy: true, Ready: true, LatencyMS: 70},
			{ID: "a", Transport: "obfs4", Healthy: true, Ready: true, LatencyMS: 45},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "b", "a", "b", "a", "b"}
	if !reflect.DeepEqual(plan.PreviewSchedule, want) {
		t.Fatalf("schedule=%v want=%v", plan.PreviewSchedule, want)
	}
	if plan.SessionIDBytes != 8 || plan.PacketLengthPrefixBytes != 2 || plan.MaxPacketBytes != 65535 || plan.QueuePackets != 32 {
		t.Fatalf("unexpected framing/bounds: %+v", plan)
	}
	if plan.StartsTransports || plan.PerformsNetworkIO || plan.WritesPackets || plan.DropsSilently {
		t.Fatalf("planner gained runtime authority: %+v", plan)
	}
}

func TestPostRefactor232MultipathRandomIsDeterministic(t *testing.T) {
	req := MultipathTransportPlanRequest{Algorithm: "random", SelectionSeed: "fixture-seed", PreviewPackets: 12, Paths: []MultipathPathObservation{
		{ID: "one", Transport: "obfs4", Healthy: true, Ready: true},
		{ID: "two", Transport: "webtunnel", Healthy: true, Ready: true},
		{ID: "three", Transport: "snowflake", Healthy: true, Ready: true},
	}}
	a, err := BuildMultipathTransportPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildMultipathTransportPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.PreviewSchedule, b.PreviewSchedule) {
		t.Fatalf("random schedule is not reproducible: %v vs %v", a.PreviewSchedule, b.PreviewSchedule)
	}
}

func TestPostRefactor232MultipathRejectsUnsafeOrAmbiguousInputs(t *testing.T) {
	base := []MultipathPathObservation{{ID: "a", Transport: "obfs4", Healthy: true, Ready: true}, {ID: "b", Transport: "webtunnel", Healthy: true, Ready: true}}
	cases := []MultipathTransportPlanRequest{
		{Algorithm: "weighted", Paths: base},
		{Algorithm: "round-robin", QueuePackets: 4097, Paths: base},
		{Algorithm: "round-robin", OverflowPolicy: "drop-old", Paths: base},
		{Algorithm: "round-robin", Paths: []MultipathPathObservation{{ID: "a", Transport: "obfs4", Healthy: true, Ready: true}, {ID: "a", Transport: "webtunnel", Healthy: true, Ready: true}}},
		{Algorithm: "round-robin", Paths: []MultipathPathObservation{{ID: "a", Transport: "obfs4", Healthy: true, Ready: true}, {ID: "b", Transport: "webtunnel", Healthy: false, Ready: true}}},
	}
	for i, tc := range cases {
		if _, err := BuildMultipathTransportPlan(tc); err == nil {
			t.Fatalf("case %d unexpectedly accepted", i)
		}
	}
}

func TestPostRefactor232DNSCampaignLifecycleAndBatching(t *testing.T) {
	plan, err := BuildDNSResolverCampaignPlan(DNSResolverCampaignPlanRequest{Mode: "dns", Platform: "linux", ObservedState: "running", RequestedAction: "pause", Domain: "example.com", QueryType: "A", CandidateCount: 1024, Concurrency: 100, RandomSubdomain: true, SelectionSeed: "seed"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.BatchSize != 16 || !plan.ActionAllowed || plan.NextState != "paused" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.CacheBustLabel == "" {
		t.Fatal("cache bust label missing")
	}
	again, _ := BuildDNSResolverCampaignPlan(DNSResolverCampaignPlanRequest{Mode: "dns", Platform: "linux", ObservedState: "running", RequestedAction: "pause", Domain: "example.com", QueryType: "A", CandidateCount: 1024, Concurrency: 100, RandomSubdomain: true, SelectionSeed: "seed"})
	if plan.CacheBustLabel != again.CacheBustLabel {
		t.Fatalf("cache label not deterministic: %q vs %q", plan.CacheBustLabel, again.CacheBustLabel)
	}
	if plan.DownloadsClients || plan.MutatesMTU || plan.PerformsNetworkIO || plan.StartsWorkerThread {
		t.Fatalf("planner gained runtime authority: %+v", plan)
	}

	small, err := BuildDNSResolverCampaignPlan(DNSResolverCampaignPlanRequest{Mode: "dns", Platform: "windows", Domain: "example.com", CandidateCount: 8, Concurrency: 8})
	if err != nil {
		t.Fatal(err)
	}
	if small.BatchSize != 4 {
		t.Fatalf("small batch=%d want=4", small.BatchSize)
	}

	resume, err := BuildDNSResolverCampaignPlan(DNSResolverCampaignPlanRequest{Mode: "slipnet", Platform: "linux", ObservedState: "paused", RequestedAction: "resume", Domain: "example.com", CandidateCount: 100, QuerySize: 50})
	if err != nil {
		t.Fatal(err)
	}
	if !resume.ActionAllowed || resume.NextState != "running" {
		t.Fatalf("resume contract broken: %+v", resume)
	}

	invalidTransition, err := BuildDNSResolverCampaignPlan(DNSResolverCampaignPlanRequest{Mode: "dns", Platform: "linux", ObservedState: "idle", RequestedAction: "pause", Domain: "example.com", CandidateCount: 100})
	if err != nil {
		t.Fatal(err)
	}
	if invalidTransition.ActionAllowed || invalidTransition.NextState != "idle" || len(invalidTransition.Warnings) == 0 {
		t.Fatalf("invalid transition should remain read-only evidence: %+v", invalidTransition)
	}
}

func TestPostRefactor232DNSCampaignRejectsWrongModeBounds(t *testing.T) {
	bad := []DNSResolverCampaignPlanRequest{
		{Mode: "dns", Platform: "linux", Domain: "example.com", CandidateCount: 1, QuerySize: 50},
		{Mode: "slipnet", Platform: "linux", Domain: "example.com", CandidateCount: 1, QuerySize: 49},
		{Mode: "dns", Platform: "linux", Domain: "1.2.3.4", CandidateCount: 1},
		{Mode: "dns", Platform: "linux", Domain: "example.com", CandidateCount: 10_000_001},
	}
	for i, req := range bad {
		if _, err := BuildDNSResolverCampaignPlan(req); err == nil {
			t.Fatalf("case %d unexpectedly accepted", i)
		}
	}
}

func TestPostRefactor232OutlineStaticDynamicAndInvite(t *testing.T) {
	static := "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@example.com:8388#SSTest"
	plan, err := BuildOutlineAccessPlan(OutlineAccessPlanRequest{Candidate: static})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind != "static" || !plan.StaticValid || plan.FingerprintSHA256 == "" {
		t.Fatalf("unexpected static plan: %+v", plan)
	}
	rendered := strings.ToLower(strings.Join(append([]string{plan.FingerprintSHA256, plan.Kind, plan.RemoteConfigURL}, plan.Warnings...), "|"))
	if strings.Contains(rendered, "password") || strings.Contains(rendered, "cGFzc3dvcmQ=") {
		t.Fatalf("credential leaked in plan: %s", rendered)
	}
	if plan.PerformsNetworkIO || plan.PersistsSecret {
		t.Fatalf("planner gained authority: %+v", plan)
	}

	invite := "https://invite.example/#ss%3A%2F%2FYWVzLTEyOC1nY206cGFzc3dvcmQ%3D%40example.com%3A8388%23SSTest"
	inv, err := BuildOutlineAccessPlan(OutlineAccessPlanRequest{Candidate: invite})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Kind != "static" || !inv.InviteUnwrapped || !inv.StaticValid {
		t.Fatalf("invite not unwrapped: %+v", inv)
	}

	dyn, err := BuildOutlineAccessPlan(OutlineAccessPlanRequest{Candidate: "ssconf://provider.example/key"})
	if err != nil {
		t.Fatal(err)
	}
	if dyn.Kind != "dynamic" || !dyn.RemoteFetchNeeded || dyn.RemoteConfigURL != "https://provider.example/key" || dyn.PerformsNetworkIO {
		t.Fatalf("dynamic boundary broken: %+v", dyn)
	}
	if _, err := BuildOutlineAccessPlan(OutlineAccessPlanRequest{Candidate: "ssconf://localhost/key"}); err == nil {
		t.Fatal("localhost dynamic config admitted")
	}
	if _, err := BuildOutlineAccessPlan(OutlineAccessPlanRequest{Candidate: "ssconf://127.0.0.1/key"}); err == nil {
		t.Fatal("private IP dynamic config admitted")
	}
}
