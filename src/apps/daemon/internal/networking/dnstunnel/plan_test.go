package dnstunnel

import (
	"math"
	"testing"
)

func TestBuildPlan(t *testing.T) {
	p, err := BuildPlan(PlanRequest{Suffix: "vpn.example.com", PayloadBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if p.FramePayloadBytes <= 0 || p.Fragments < 2 {
		t.Fatalf("plan=%+v", p)
	}
	if _, err := BuildPlan(PlanRequest{Suffix: string(make([]byte, 201)), PayloadBytes: 1}); err == nil {
		t.Fatal("expected long suffix error")
	}
}

func TestBuildPlanRejectsInvalidEncodingAndBudget(t *testing.T) {
	if _, err := BuildPlan(PlanRequest{Suffix: "vpn.example.com", PayloadBytes: 1, Encoding: "hex"}); err == nil {
		t.Fatal("expected encoding rejection")
	}
	if _, err := BuildPlan(PlanRequest{Suffix: "vpn.example.com", PayloadBytes: 1, UDPBudget: 128}); err == nil {
		t.Fatal("expected UDP budget rejection")
	}
}

func floatp(v float64) *float64 { return &v }
func intp(v int) *int           { return &v }

func TestReliabilityPlanPresetAndExplicitPrecedence(t *testing.T) {
	p, err := BuildPlan(PlanRequest{
		Suffix: "vpn.example.com", PayloadBytes: 4096,
		Preset: "survival", ObservedLossPct: floatp(30),
		FECLossThresholdPct: floatp(35), FECBaseParity: intp(2), PreferredTransport: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Reliability.Preset != "survival" || p.Reliability.PreferredTransport != "tcp" {
		t.Fatalf("reliability=%+v", p.Reliability)
	}
	if p.Reliability.Mode != "raw" {
		t.Fatalf("explicit 35%% threshold did not override survival preset: %+v", p.Reliability)
	}
	if p.Reliability.BaseParityShards != 2 {
		t.Fatalf("base parity=%d", p.Reliability.BaseParityShards)
	}
}

func TestReliabilityPlanBandsAndRecoveryTarget(t *testing.T) {
	cases := []struct {
		loss float64
		mode string
	}{
		{1, "raw"}, {25, "fec"}, {80, "super-fec"}, {90, "arq-primary"},
	}
	for _, tc := range cases {
		p, err := BuildPlan(PlanRequest{Suffix: "vpn.example.com", Preset: "speed", ObservedLossPct: floatp(tc.loss)})
		if err != nil {
			t.Fatalf("loss %.0f: %v", tc.loss, err)
		}
		if p.Reliability.Mode != tc.mode {
			t.Fatalf("loss %.0f mode=%s want=%s plan=%+v", tc.loss, p.Reliability.Mode, tc.mode, p.Reliability)
		}
		if p.Reliability.DataShards+p.Reliability.ParityShards > 256 {
			t.Fatalf("loss %.0f exceeds shard cap: %+v", tc.loss, p.Reliability)
		}
		if tc.mode == "super-fec" && p.Reliability.RecoveryProbabilityPct < 89.9 {
			t.Fatalf("super FEC recovery=%f", p.Reliability.RecoveryProbabilityPct)
		}
		if tc.mode == "arq-primary" && p.Reliability.ParityShards > p.Reliability.BaseParityShards {
			t.Fatalf("hopeless link kept escalating FEC: %+v", p.Reliability)
		}
	}
}

func TestReliabilityResolverTiersAndGoodputRanking(t *testing.T) {
	p, err := BuildPlan(PlanRequest{Suffix: "vpn.example.com", Resolvers: []ResolverObservation{
		{Name: "fast-large", Reachable: true, MTU: 1232, LossPct: 10, RTTMs: 40, ThroughputKbps: 800},
		{Name: "lossy-large", Reachable: true, MTU: 1232, LossPct: 60, RTTMs: 30, ThroughputKbps: 900},
		{Name: "small-backup", Reachable: true, MTU: 800, LossPct: 0, RTTMs: 20, ThroughputKbps: 700},
		{Name: "dead", Reachable: false, MTU: 1400, LossPct: 0, RTTMs: 10, ThroughputKbps: 1000},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Reliability.Resolvers) != 4 {
		t.Fatalf("resolver rows=%d", len(p.Reliability.Resolvers))
	}
	rows := map[string]ResolverPlan{}
	for _, row := range p.Reliability.Resolvers {
		rows[row.Name] = row
	}
	if rows["dead"].Tier != "invalid" {
		t.Fatalf("dead=%+v", rows["dead"])
	}
	if rows["small-backup"].Tier != "reserve" {
		t.Fatalf("small=%+v", rows["small-backup"])
	}
	if rows["fast-large"].Tier != "active" || rows["lossy-large"].Tier != "active" {
		t.Fatalf("active tiers=%+v %+v", rows["fast-large"], rows["lossy-large"])
	}
	if !(rows["fast-large"].EffectiveGoodputKbps > rows["lossy-large"].EffectiveGoodputKbps) {
		t.Fatalf("loss was not discounted: %+v", p.Reliability.Resolvers)
	}
	if p.Reliability.Resolvers[0].Name != "fast-large" {
		t.Fatalf("ranking=%+v", p.Reliability.Resolvers)
	}
}

func TestReliabilityPlanRejectsNonFiniteAndUnboundedEvidence(t *testing.T) {
	nan := math.NaN()
	if _, err := BuildPlan(PlanRequest{Suffix: "vpn.example.com", ObservedLossPct: &nan}); err == nil {
		t.Fatal("NaN loss accepted")
	}
	tooMany := make([]ResolverObservation, maxReliabilityResolvers+1)
	for i := range tooMany {
		tooMany[i] = ResolverObservation{Name: "r", Reachable: true, MTU: 1000}
	}
	if _, err := BuildPlan(PlanRequest{Suffix: "vpn.example.com", Resolvers: tooMany}); err == nil {
		t.Fatal("resolver evidence limit not enforced")
	}
}
