package diagnostics

import "testing"

func TestPostRefactor235ScanLoadTimeoutsDoNotProveCongestion(t *testing.T) {
	p, err := BuildScanLoadPolicyPlan(ScanLoadPolicyRequest{CurrentConcurrency: 100, MinConcurrency: 3, MaxConcurrency: 400, GatewayRTTMS: 20, BaselineRTTMS: 20, TimeoutRatePct: 90, SampleCount: 100, CandidateCount: 10, RequestedWorkers: 4})
	if err != nil {
		t.Fatal(err)
	}
	if p.Action != "increase" || p.NextConcurrency != 105 || !p.TimeoutInformationalOnly {
		t.Fatalf("unexpected plan: %+v", p)
	}
	want := []int{3, 3, 2, 2}
	if len(p.ChunkSizes) != len(want) {
		t.Fatalf("chunks=%v", p.ChunkSizes)
	}
	for i := range want {
		if p.ChunkSizes[i] != want[i] {
			t.Fatalf("chunks=%v", p.ChunkSizes)
		}
	}
}

func TestPostRefactor235ScanLoadGatewayBackoff(t *testing.T) {
	p, err := BuildScanLoadPolicyPlan(ScanLoadPolicyRequest{CurrentConcurrency: 100, MinConcurrency: 10, MaxConcurrency: 400, GatewayRTTMS: 70, BaselineRTTMS: 20, TimeoutRatePct: 0, SampleCount: 100, CandidateCount: 100})
	if err != nil {
		t.Fatal(err)
	}
	if p.Action != "backoff" || p.NextConcurrency != 70 || p.HealthState != "congested" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestPostRefactor235MobileReadiness(t *testing.T) {
	p, err := BuildMobileConnectionReadinessPlan(MobileConnectionReadinessRequest{Phase: "connected", ActiveResolvers: []string{"a", "a"}, ValidResolvers: []string{"a", "b"}, RuntimeHealthy: true, WarmupCompleted: true})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Ready || p.Percent != 100 || len(p.ActiveResolvers) != 1 {
		t.Fatalf("unexpected: %+v", p)
	}
	p, _ = BuildMobileConnectionReadinessPlan(MobileConnectionReadinessRequest{Phase: "connected", ActiveResolvers: []string{"a"}, ValidResolvers: []string{"a"}, RuntimeHealthy: true, WarmupCompleted: false})
	if p.Ready || p.State != "connected-not-ready" {
		t.Fatalf("warmup must gate readiness: %+v", p)
	}
}

func TestPostRefactor235ConfigFallbackStopsOnInvalid(t *testing.T) {
	p, err := BuildConfigFallbackPlan(ConfigFallbackRequest{Candidates: []ConfigFallbackCandidate{{ID: "a", Kind: "websocket", Status: "unsupported"}, {ID: "b", Kind: "shadowsocks", Status: "invalid"}, {ID: "c", Kind: "proxyless", Status: "supported"}}})
	if err != nil {
		t.Fatal(err)
	}
	if p.SelectedID != "" || p.BlockingCandidate != "b" || len(p.SkippedUnsupported) != 1 {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestPostRefactor235DNSInterceptIsLazy(t *testing.T) {
	p, err := BuildDNSInterceptSafetyPlan(DNSInterceptSafetyRequest{DestinationPort: 53, DestinationIsLocalResolver: true, Transport: "udp", PacketBytes: 80})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Intercept || !p.RequireTCPRetry || p.CreateBaseSession || p.ForwardToBase {
		t.Fatalf("unexpected: %+v", p)
	}
	p, _ = BuildDNSInterceptSafetyPlan(DNSInterceptSafetyRequest{DestinationPort: 443, DestinationIsLocalResolver: false, Transport: "udp", PacketBytes: 80})
	if !p.ForwardToBase || !p.CreateBaseSession {
		t.Fatalf("base path should be created lazily: %+v", p)
	}
}

func TestPostRefactor235TorConsensusFamilyAndFreshness(t *testing.T) {
	fp1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fp2 := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	p, err := BuildTorConsensusEvidencePlan(TorConsensusEvidenceRequest{NowUnix: 150, ValidAfterUnix: 100, FreshUntilUnix: 200, Relays: []TorConsensusRelayObservation{{Fingerprint: fp1, IPv4: "1.2.3.4", Flags: []string{"Running", "Valid", "Exit"}, Family: []string{"$" + fp2}, BandwidthWeight: 10, ExitAllowedPorts: []int{80, 443}}, {Fingerprint: fp2, IPv4: "1.2.8.9", Flags: []string{"Running", "Valid"}, BandwidthWeight: 20}}})
	if err != nil {
		t.Fatal(err)
	}
	if p.ConsensusState != "fresh" || p.RunningValid != 2 || len(p.FamilyAsymmetries) != 1 || len(p.SharedIPv4Prefix16) != 1 || p.ExitPorts[443] != 1 {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestPostRefactor235DNSCryptTopologyRequiresTrustedRelay(t *testing.T) {
	p, err := BuildDNSCryptTopologyPlan(DNSCryptTopologyRequest{MaxSourceAgeHours: 24, Resolvers: []DNSCryptTopologyResolver{{Name: "r1", Protocol: "dnscrypt", SourceSigned: true, SourceAgeHours: 1, RequiresRelay: true}, {Name: "r2", Protocol: "doh", SourceSigned: false, SourceAgeHours: 1}}, Relays: []DNSCryptTopologyRelay{{Name: "relay", Protocols: []string{"dnscrypt"}, SourceSigned: true, SourceAgeHours: 2, Available: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.EligibleResolvers) != 1 || len(p.Pairings) != 1 || p.Rejected["r2"] == "" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestPostRefactor235EvidenceReceiptDetectsMissingAndUnknown(t *testing.T) {
	h1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	h2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	missing := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	p, err := BuildEvidenceReceiptTopologyPlan(EvidenceReceiptRequest{Artifacts: []EvidenceReceiptObservation{{ID: "root", SHA256: h1, SignatureStatus: "pass", TimestampStatus: "pass", MetadataConsent: true}, {ID: "leaf", SHA256: h2, ParentSHA256: missing, SignatureStatus: "unknown", TimestampStatus: "pass", MetadataConsent: false}}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Complete || len(p.MissingParents) != 1 || len(p.UnknownEvidence) != 1 || len(p.MetadataWithoutConsent) != 1 {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestPostRefactor235DNSFilterPreset(t *testing.T) {
	p, err := BuildDNSFilterPresetPlan(DNSFilterPresetRequest{Intent: "anti-bypass", Lists: []DNSFilterListObservation{{Name: "doh-vpn-proxy-bypass", Category: "doh", Format: "adblock", Entries: 100}, {Name: "ads", Category: "ads", Format: "hosts", Entries: 50}, {Name: "exceptions", Category: "allow", Format: "hosts", Entries: 10, AllowExceptions: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Selected) != 1 || p.Selected[0] != "doh-vpn-proxy-bypass" || len(p.Optional) != 1 || p.TotalEntries != 100 {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestPostRefactor235APITraceMergesFieldsAndRedactsSensitiveHeaders(t *testing.T) {
	p, err := BuildAPITraceSchemaPlan(APITraceSchemaRequest{Observations: []APITraceObservation{{Method: "GET", Path: "/users/42?q=secret", Status: 200, ContentType: "application/json", QueryKeys: []string{"q"}, HeaderKeys: []string{"Accept", "Authorization"}, BodyFields: []string{"name"}}, {Method: "GET", Path: "/users/43", Status: 404, ContentType: "application/json", QueryKeys: []string{"page"}, HeaderKeys: []string{"accept", "Cookie"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Endpoints) != 1 {
		t.Fatalf("endpoints=%+v", p.Endpoints)
	}
	e := p.Endpoints[0]
	if e.PathTemplate != "/users/{id}" || len(e.QueryKeys) != 2 || len(e.HeaderKeys) != 1 || e.HeaderKeys[0] != "accept" || e.SensitiveFieldsOmitted != 2 {
		t.Fatalf("unexpected endpoint: %+v", e)
	}
}

func TestPostRefactor235ProcessRuleFindsConflictAndShadow(t *testing.T) {
	p, err := BuildProcessProxyRulePlan(ProcessProxyRuleRequest{ProxyProcess: "proxy.exe", Rules: []ProcessProxyRuleObservation{{Process: "app.exe", Protocol: "both", Target: "*", Action: "proxy", PortStart: 1, PortEnd: 65535, Priority: 1}, {Process: "app.exe", Protocol: "tcp", Target: "1.2.3.4", Action: "direct", PortStart: 443, PortEnd: 443, Priority: 2}, {Process: "proxy.exe", Protocol: "tcp", Target: "*", Action: "proxy", PortStart: 1, PortEnd: 65535, Priority: 3}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Findings) == 0 || p.Findings[0].Kind != "shadowed" || len(p.ProxyLoopRisks) != 1 {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestPostRefactor235NetworkEvidenceBundleComposesWithoutAuthority(t *testing.T) {
	scan := ScanLoadPolicyRequest{CurrentConcurrency: 10, MinConcurrency: 3, MaxConcurrency: 50, SampleCount: 40, GatewayRTTMS: 15, BaselineRTTMS: 10}
	filter := DNSFilterPresetRequest{Intent: "security", Lists: []DNSFilterListObservation{{Name: "threat-intelligence", Category: "security"}}}
	p, err := BuildNetworkEvidenceBundlePlan(NetworkEvidenceBundleRequest{ScanLoad: &scan, DNSFilter: &filter})
	if err != nil {
		t.Fatal(err)
	}
	if !p.ReadOnly || len(p.Selected) != 2 {
		t.Fatalf("unexpected bundle: %+v", p)
	}
	if p.Status != "ready" {
		t.Fatalf("expected ready aggregate, got %+v", p)
	}
}
