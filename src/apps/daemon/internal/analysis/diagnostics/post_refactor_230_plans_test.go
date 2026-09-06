package diagnostics

import (
	"strings"
	"testing"
)

func Test230TorBridgeSelectionFiltersBeforeDeterministicRank(t *testing.T) {
	req := TorBridgeSelectionRequest{Country: "ir", Transport: "obfs4", RequireStable: true, SelectionKey: "client-bucket", Candidates: []TorBridgeSelectionCandidate{
		{ID: "a", Transport: "obfs4", Address: "1.1.1.1:443", AddressFamily: "4", Running: true, Stable: true},
		{ID: "blocked", Transport: "obfs4", Address: "8.8.8.8:443", AddressFamily: "4", Running: true, Stable: true, BlockedIn: []string{"IR"}},
		{ID: "unstable", Transport: "obfs4", Address: "9.9.9.9:443", AddressFamily: "4", Running: true},
		{ID: "snowflake", Transport: "snowflake", Address: "broker.example:443", Running: true, Stable: true},
	}}
	first, err := BuildTorBridgeSelectionPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildTorBridgeSelectionPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Selected) != 1 || first.Selected[0].ID != "a" || first.Selected[0].RankHash != second.Selected[0].RankHash {
		t.Fatalf("selection=%+v", first)
	}
	if first.Rejected["blocked"] != "blocked-in-country" || first.Rejected["unstable"] != "not-stable" || first.Rejected["snowflake"] != "transport-mismatch" {
		t.Fatalf("rejected=%v", first.Rejected)
	}
	if first.FetchesBridges || first.PersistsClientKey || first.PerformsNetworkIO || !first.ReadOnly {
		t.Fatalf("authority=%+v", first)
	}
}

func Test230TorBridgeAdaptiveCountIsBounded(t *testing.T) {
	candidates := make([]TorBridgeSelectionCandidate, 0, 120)
	for i := 0; i < 120; i++ {
		candidates = append(candidates, TorBridgeSelectionCandidate{ID: string(rune('a'+(i%26))) + strings.Repeat("x", i/26), Address: "1.1.1.1:443", Running: true})
	}
	plan, err := BuildTorBridgeSelectionPlan(TorBridgeSelectionRequest{Candidates: candidates})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Selected) != 3 || !plan.AdaptiveCount {
		t.Fatalf("adaptive=%+v", plan)
	}
}

func Test230TorBootstrapReadinessRequiresControlAuthCircuitAndSOCKS(t *testing.T) {
	ready, err := BuildTorBootstrapEvidencePlan(TorBootstrapEvidenceRequest{ControlConnected: true, Authenticated: true, SafeCookieAvailable: true, NetworkEnabled: true, BootstrapProgress: 100, CircuitEstablished: true, SocksListeners: 1, StreamIsolation: true})
	if err != nil {
		t.Fatal(err)
	}
	if !ready.Ready || ready.State != "ready" || ready.ControlsTor || ready.ReadsCookieBytes || ready.PerformsNetworkIO {
		t.Fatalf("ready=%+v", ready)
	}
	for name, req := range map[string]TorBootstrapEvidenceRequest{
		"auth":      {ControlConnected: true, NetworkEnabled: true, BootstrapProgress: 100, CircuitEstablished: true, SocksListeners: 1},
		"bootstrap": {ControlConnected: true, Authenticated: true, NetworkEnabled: true, BootstrapProgress: 80, CircuitEstablished: true, SocksListeners: 1},
		"circuit":   {ControlConnected: true, Authenticated: true, NetworkEnabled: true, BootstrapProgress: 100, SocksListeners: 1},
	} {
		plan, err := BuildTorBootstrapEvidencePlan(req)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Ready {
			t.Fatalf("%s unexpectedly ready: %+v", name, plan)
		}
	}
}

func Test230CensorshipEvidenceRequiresControlsForStrongClaim(t *testing.T) {
	plan, err := BuildCensorshipMeasurementPlan(CensorshipMeasurementRequest{Observations: []CensorshipObservation{
		{ID: "dns", Kind: "dns", ExperimentObserved: true, ExperimentSuccess: false, ControlObserved: true, ControlSuccess: true},
		{ID: "tls", Kind: "tls", ExperimentObserved: true, ExperimentSuccess: false, ControlObserved: false},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Conclusion != "differential-anomaly-detected" || plan.Confidence != "strong" || plan.ComparablePairs != 1 || len(plan.MissingControls) != 1 {
		t.Fatalf("plan=%+v", plan)
	}
	if plan.PerformsProbes || plan.AppliesEvasion || !plan.ReadOnly {
		t.Fatalf("authority=%+v", plan)
	}
	if plan.Anomalies[0].Strength != "strong" {
		t.Fatalf("anomalies=%+v", plan.Anomalies)
	}
}

func Test230CensorshipEvidenceDoesNotPromoteExperimentFailureAlone(t *testing.T) {
	plan, err := BuildCensorshipMeasurementPlan(CensorshipMeasurementRequest{Observations: []CensorshipObservation{{ID: "tcp", Kind: "tcp", ExperimentObserved: true, ExperimentSuccess: false}}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Confidence != "weak" || len(plan.Anomalies) != 1 || plan.Anomalies[0].Strength != "weak" {
		t.Fatalf("plan=%+v", plan)
	}
}

func Test230DTLSPolicySecureDefaultsAndBounds(t *testing.T) {
	plan, err := BuildDTLSSessionPolicyPlan(DTLSSessionPolicyRequest{Role: "server", IdentityMode: "certificate", CertificateConfigured: true, SessionResumption: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.MTU != 1200 || plan.ReplayProtectionWindow != 64 || plan.FlightIntervalMillis != 1000 || !plan.RetransmitBackoff || plan.ExtendedMasterSecret != "require" {
		t.Fatalf("defaults=%+v", plan)
	}
	if plan.PerformsHandshake || plan.WritesKeyLog || !plan.ReadOnly {
		t.Fatalf("authority=%+v", plan)
	}
	for name, req := range map[string]DTLSSessionPolicyRequest{
		"skip-verify":                         {IdentityMode: "certificate", CertificateConfigured: true, InsecureSkipVerify: true},
		"hello-bypass":                        {Role: "server", IdentityMode: "certificate", CertificateConfigured: true, InsecureSkipVerifyHello: true},
		"keylog":                              {IdentityMode: "certificate", CertificateConfigured: true, KeyLogEnabled: true},
		"replay-zero-impossible-via-negative": {IdentityMode: "certificate", CertificateConfigured: true, ReplayProtectionWindow: -1},
		"no-backoff":                          {IdentityMode: "certificate", CertificateConfigured: true, DisableRetransmitBackoff: true},
	} {
		if _, err := BuildDTLSSessionPolicyPlan(req); err == nil {
			t.Fatalf("%s admitted", name)
		}
	}
}

func Test230PhantomPoolRequiresFreshNotLivePublicEvidence(t *testing.T) {
	plan, err := BuildPhantomPoolPlan(PhantomPoolRequest{NowUnix: 1000, MaxAgeSeconds: 120, SelectionKey: "seed", Count: 2, Candidates: []PhantomPoolCandidate{
		{ID: "free", Address: "1.1.1.1", Transport: "min", Liveness: "not-live", CheckedAtUnix: 950, Weight: 2},
		{ID: "occupied", Address: "8.8.8.8", Liveness: "live", CheckedAtUnix: 950},
		{ID: "stale", Address: "9.9.9.9", Liveness: "not-live", CheckedAtUnix: 100},
		{ID: "private", Address: "10.0.0.1", Liveness: "not-live", CheckedAtUnix: 950},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Selected) != 1 || plan.Selected[0].ID != "free" {
		t.Fatalf("selected=%+v", plan.Selected)
	}
	if plan.Rejected["occupied"] != "liveness-not-confirmed-free" || plan.Rejected["stale"] != "stale-liveness-evidence" || plan.Rejected["private"] != "non-public-address" {
		t.Fatalf("rejected=%v", plan.Rejected)
	}
	if plan.PerformsLivenessProbe || plan.RegistersPhantom || plan.PerformsNetworkIO || !plan.ReadOnly {
		t.Fatalf("authority=%+v", plan)
	}
}

func Test230FlowFilterIsLiteralMetadataOnly(t *testing.T) {
	plan, err := BuildFlowFilterPlan(FlowFilterPlanRequest{Match: "all", Clauses: []FlowFilterClause{{Field: "destination", Operator: "contains", Value: "example.com"}, {Field: "protocol", Operator: "eq", Value: "tls"}}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Canonical != "all(destination:contains:example.com,protocol:eq:tls)" {
		t.Fatalf("canonical=%q", plan.Canonical)
	}
	if plan.ReadsFlowBodies || plan.ModifiesFlows || plan.ReplaysFlows || !plan.ReadOnly {
		t.Fatalf("authority=%+v", plan)
	}
	if _, err := BuildFlowFilterPlan(FlowFilterPlanRequest{Clauses: []FlowFilterClause{{Field: "body", Operator: "contains", Value: "secret"}}}); err == nil {
		t.Fatal("body filter admitted")
	}
}

func Test230PublicCDNAdmissionRejectsPrivateAndDocumentationBeforeActiveScan(t *testing.T) {
	if _, err := GeneratePublicCdnIPs([]string{"192.168.1.0/24"}, 2); err == nil {
		t.Fatal("private range admitted for active scan")
	}
	if _, err := GeneratePublicCdnIPs([]string{"192.0.2.1"}, 1); err == nil {
		t.Fatal("documentation address admitted for active scan")
	}
	ips, err := GeneratePublicCdnIPs([]string{"1.1.1.0/30"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) == 0 {
		t.Fatal("public range produced no candidates")
	}
}

func Test230MultiplexPolicyCarriesSMUXProtocolBounds(t *testing.T) {
	plan, err := BuildMultiplexPolicyPlan(MultiplexPolicyRequest{Protocol: "smux", Version: 2, KeepAliveIntervalMS: 5000, KeepAliveTimeoutMS: 15000, MaxFrameSize: 16384, MaxReceiveBuffer: 1 << 20, MaxStreamBuffer: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Version != 2 || plan.MaxFrameSize != 16384 || plan.MaxReceiveBuffer != (1<<20) || plan.MaxStreamBuffer != (64<<10) || plan.KeepAliveTimeoutMS != 15000 {
		t.Fatalf("plan=%+v", plan)
	}
	if _, err := BuildMultiplexPolicyPlan(MultiplexPolicyRequest{Protocol: "smux", KeepAliveIntervalMS: 30000, KeepAliveTimeoutMS: 10000}); err == nil {
		t.Fatal("keepalive timeout shorter than interval admitted")
	}
	if _, err := BuildMultiplexPolicyPlan(MultiplexPolicyRequest{Protocol: "smux", MaxFrameSize: 70000}); err == nil {
		t.Fatal("oversized frame admitted")
	}
	if _, err := BuildMultiplexPolicyPlan(MultiplexPolicyRequest{Protocol: "smux", MaxFrameSize: 32768, MaxReceiveBuffer: 65536, MaxStreamBuffer: 16384}); err == nil {
		t.Fatal("stream buffer smaller than frame admitted")
	}
}

func Test230HiddifyInspiredGatewayPresetStaysTopologyOnly(t *testing.T) {
	plan, err := BuildGatewayCompositionPlan(GatewayCompositionRequest{Preset: "layered-fronted-egress"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ingress", "path-router", "detour", "egress-tunnel", "health"}
	if strings.Join(plan.StartOrder, ",") != strings.Join(want, ",") {
		t.Fatalf("start order=%v", plan.StartOrder)
	}
	if plan.Downloads || plan.WritesServiceConfig {
		t.Fatalf("preset gained deployment authority: %+v", plan)
	}
}

func Test230PlannerInvariantsStateNoHiddenAuthority(t *testing.T) {
	bridge, _ := BuildTorBridgeSelectionPlan(TorBridgeSelectionRequest{Candidates: []TorBridgeSelectionCandidate{{ID: "a", Address: "1.1.1.1:443", Running: true}}})
	tor, _ := BuildTorBootstrapEvidencePlan(TorBootstrapEvidenceRequest{})
	censor, _ := BuildCensorshipMeasurementPlan(CensorshipMeasurementRequest{Observations: []CensorshipObservation{{ID: "a", Kind: "dns", ExperimentObserved: true}}})
	dtls, _ := BuildDTLSSessionPolicyPlan(DTLSSessionPolicyRequest{IdentityMode: "certificate", CertificateConfigured: true})
	phantom, _ := BuildPhantomPoolPlan(PhantomPoolRequest{NowUnix: 10, Candidates: []PhantomPoolCandidate{{ID: "a", Address: "1.1.1.1", Liveness: "not-live", CheckedAtUnix: 9}}})
	flow, _ := BuildFlowFilterPlan(FlowFilterPlanRequest{Clauses: []FlowFilterClause{{Field: "owner", Operator: "eq", Value: "x"}}})
	joined := strings.Join(append(append(append(append(append(bridge.Invariants, tor.Invariants...), censor.Invariants...), dtls.Invariants...), phantom.Invariants...), flow.Invariants...), "\n")
	for _, needle := range []string{"never contacts a distributor", "never launches Tor", "never performs DNS", "performs no DTLS handshake", "neither probes liveness nor registers", "cannot modify, replay, intercept, or close"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("missing invariant %q", needle)
		}
	}
}
