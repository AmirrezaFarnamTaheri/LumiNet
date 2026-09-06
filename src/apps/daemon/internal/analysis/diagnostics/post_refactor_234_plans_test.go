package diagnostics

import "testing"

func TestPostRefactor234DNSBlocklistCorpus(t *testing.T) {
	p, err := BuildDNSBlocklistCorpusPlan(DNSBlocklistCorpusRequest{Lists: []DNSBlocklistObservation{
		{Name: "multi", Category: "security", Format: "domains", Entries: 100, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Name: "multi-copy", Category: "security", Format: "domains", Entries: 100, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}})
	if err != nil || p.Accepted != 2 || p.TotalEntries != 200 || len(p.DuplicateDigests) != 1 || p.CoverageSHA256 == "" {
		t.Fatalf("unexpected %+v %v", p, err)
	}
	if p.FetchesFeeds || p.AppliesBlocking || p.WritesFiles || p.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", p)
	}
}

func TestPostRefactor234APITraceSchema(t *testing.T) {
	p, err := BuildAPITraceSchemaPlan(APITraceSchemaRequest{Observations: []APITraceObservation{
		{Method: "GET", Path: "/users/123?token=secret", Status: 200, ContentType: "application/json; charset=utf-8"},
		{Method: "GET", Path: "/users/456", Status: 404, ContentType: "application/json"},
	}})
	if err != nil || len(p.Endpoints) != 1 || p.Endpoints[0].PathTemplate != "/users/{id}" || p.Endpoints[0].Samples != 2 {
		t.Fatalf("unexpected %+v %v", p, err)
	}
	if p.CapturesTraffic || p.RunsMITM || p.WritesSpecification || p.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", p)
	}
}

func TestPostRefactor234TorDescriptorEvidence(t *testing.T) {
	p, err := BuildTorDescriptorEvidencePlan(TorDescriptorEvidenceRequest{Relays: []TorRelayObservation{{Fingerprint: "0123456789abcdef0123456789abcdef01234567", Country: "se", Flags: []string{"Running", "Valid", "Exit"}, AdvertisedBandwidthKBPS: 1000}}})
	if err != nil || p.Accepted != 1 || p.Running != 1 || p.Valid != 1 || p.Exit != 1 || p.Countries["SE"] != 1 {
		t.Fatalf("unexpected %+v %v", p, err)
	}
	if p.SelectsRelay || p.FetchesDescriptors || p.ControlsTor || p.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", p)
	}
}

func TestPostRefactor234ProcessProxyRuleLoopRisk(t *testing.T) {
	p, err := BuildProcessProxyRulePlan(ProcessProxyRuleRequest{ProxyProcess: "proxy.exe", Rules: []ProcessProxyRuleObservation{{Process: "browser.exe", Protocol: "tcp", Target: "*", Action: "proxy", PortStart: 443, Priority: 2}, {Process: "proxy.exe", Protocol: "both", Target: "0.0.0.0/0", Action: "proxy", Priority: 1}}})
	if err != nil || len(p.Accepted) != 2 || len(p.ProxyLoopRisks) != 1 || p.Accepted[0].Process != "proxy.exe" {
		t.Fatalf("unexpected %+v %v", p, err)
	}
	if p.InstallsDriver || p.AppliesRules || p.OpensSockets || p.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", p)
	}
}

func TestPostRefactor234EvidenceUnknownIsNotPass(t *testing.T) {
	p, err := BuildEvidenceChainPlan(EvidenceChainRequest{Artifacts: []EvidenceArtifactObservation{{ID: "photo", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", SignatureStatus: "pass", TimestampStatus: "unknown"}, {ID: "manifest", SHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", SignatureStatus: "pass", TimestampStatus: "pass"}}})
	if err != nil || p.Passed != 1 || p.Unknown != 1 || p.Failed != 0 || len(p.PriorityGaps) != 1 {
		t.Fatalf("unexpected %+v %v", p, err)
	}
	if p.SignsArtifacts || p.VerifiesExternally || p.ReadsFiles || p.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", p)
	}
}

func TestPostRefactor234DNSCryptResolverPolicy(t *testing.T) {
	p, err := BuildDNSCryptResolverPolicyPlan(DNSCryptResolverPolicyRequest{RequireDNSSEC: true, RequireNoLog: true, MaxLatencyMS: 500, Resolvers: []DNSCryptResolverObservation{{Name: "a", Protocol: "dnscrypt", DNSSEC: true, NoLog: true, NoFilter: true, SupportsRelay: true, LatencyMS: 50}, {Name: "b", Protocol: "doh", DNSSEC: false, NoLog: true, LatencyMS: 20}}})
	if err != nil || len(p.Eligible) != 1 || p.Eligible[0].Name != "a" || p.Rejected["b"] != "dnssec required" {
		t.Fatalf("unexpected %+v %v", p, err)
	}
	if p.FetchesResolverList || p.ChangesSystemDNS || p.StartsProxy || p.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", p)
	}
}
