package diagnostics

import "testing"

func TestPostRefactor233DNSRefinerDeterministicAndRedacted(t *testing.T) {
	p, err := BuildDNSRefinerPlan(DNSRefinerPlanRequest{AllowedSchemes: []string{"dns", "dnstt"}, OutputOrder: "ASC", Observations: []DNSRefinerObservation{{SourceKey: "b", Scheme: "dnstt", NameServer: "NS.Example.", Address: "1.2.3.4:53", HasPublicKey: true, HasPassword: true}, {SourceKey: "a", Scheme: "dns", NameServer: "dns.example", Address: "8.8.8.8"}, {SourceKey: "bad", Scheme: "slipnet", NameServer: "x.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Accepted) != 2 || p.Accepted[0].SourceKey != "a" || p.Accepted[1].NameServer != "ns.example" || p.Accepted[1].CredentialFields != 2 {
		t.Fatalf("unexpected plan %+v", p)
	}
	if p.FetchesSubscriptions || p.WritesExports || p.RevealsCredentials || p.PerformsNetworkIO || !p.ReadOnly {
		t.Fatalf("planner gained authority %+v", p)
	}
}
func TestPostRefactor233HTTPSRulesetAudit(t *testing.T) {
	p, err := BuildHTTPSUpgradeRulesetPlan(HTTPSUpgradeRulesetPlanRequest{Rules: []HTTPSUpgradeRuleObservation{{Name: "one", Targets: []string{"example.com", "*.cdn.example.com"}}, {Name: "two", Targets: []string{"example.com", "bad target"}, Disabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if p.TargetCount != 3 || p.DisabledRules != 1 || len(p.DuplicateTargets) != 1 || len(p.InvalidTargets) != 1 || p.CoverageSHA256 == "" {
		t.Fatalf("unexpected %+v", p)
	}
	if p.InstallsBrowserRules || p.RedirectsRequests || p.ExecutesRegex || p.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", p)
	}
}
func TestPostRefactor233TorExitScanBounds(t *testing.T) {
	p, err := BuildTorExitScanPlan(TorExitScanPlanRequest{CandidateExits: 100, RequestedExits: 20, Country: "de", BuildDelayMS: 50, Parallelism: 4, Modules: []string{"rtt", "dnspoison"}})
	if err != nil {
		t.Fatal(err)
	}
	if p.PlannedExits != 20 || p.Country != "DE" || p.MinimumScheduleMillis != 250 {
		t.Fatalf("unexpected %+v", p)
	}
	if p.ControlsTor || p.BuildsCircuits || p.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", p)
	}
	if _, err := BuildTorExitScanPlan(TorExitScanPlanRequest{CandidateExits: 10, BuildDelayMS: 10}); err == nil {
		t.Fatal("unsafe scan delay accepted")
	}
}
func TestPostRefactor233MobileTorLifecycle(t *testing.T) {
	p, err := BuildMobileTorLifecyclePlan(MobileTorLifecyclePlanRequest{ObservedState: "stopped", AppState: "foreground", RequestedAction: "start", NetworkAvailable: true, OnDemand: true})
	if err != nil {
		t.Fatal(err)
	}
	if !p.ActionAllowed || p.NextState != "starting" {
		t.Fatalf("unexpected %+v", p)
	}
	bg, err := BuildMobileTorLifecyclePlan(MobileTorLifecyclePlanRequest{ObservedState: "ready", AppState: "background", OnDemand: true, NetworkAvailable: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bg.ShouldRemainResident {
		t.Fatalf("expected resident %+v", bg)
	}
	if bg.ControlsTor || bg.WritesVPNConfiguration || bg.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", bg)
	}
}
func TestPostRefactor233SecurityPostureUnknownIsNotPass(t *testing.T) {
	p, err := BuildSecurityPosturePlan(SecurityPosturePlanRequest{Checks: []SecurityPostureCheck{{ID: "disk", Category: "device", Status: "pass", Severity: "critical"}, {ID: "dns", Category: "network", Status: "unknown", Severity: "high"}, {ID: "updates", Category: "os", Status: "fail", Severity: "medium"}}})
	if err != nil {
		t.Fatal(err)
	}
	if p.PassedChecks != 1 || p.UnknownChecks != 1 || p.FailedChecks != 1 || p.WeightedCoveragePercent >= 100 || len(p.PriorityGaps) != 2 {
		t.Fatalf("unexpected %+v", p)
	}
	if p.InspectsHost || p.ChangesSettings || p.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", p)
	}
}
func TestPostRefactor233TrafficShaperIsPlanningOnly(t *testing.T) {
	p, err := BuildTrafficShaperPlan(TrafficShaperPlanRequest{RateBytesPerSecond: 1000, BurstBytes: 2500, QueueBytes: 5000, PaddingMinBytes: 16, PaddingMaxBytes: 128, OverheadPercent: 10})
	if err != nil {
		t.Fatal(err)
	}
	if p.BurstDrainMillis != 2500 || p.QueueDrainMillis != 5000 || p.WorstCasePaddingBytes != 128 {
		t.Fatalf("unexpected %+v", p)
	}
	if p.AppliesShaping || p.GeneratesPadding || p.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", p)
	}
}
func TestPostRefactor233LocationEvidence(t *testing.T) {
	p, err := BuildEndpointLocationEvidencePlan(EndpointLocationEvidencePlanRequest{MinimumConfidence: .8, Observations: []EndpointLocationObservation{{EndpointID: "a", AdvertisedCountry: "SE", MeasuredCountry: "se", Source: "caller", Confidence: .9}, {EndpointID: "b", AdvertisedCountry: "US", MeasuredCountry: "DE", Source: "caller", Confidence: .95}, {EndpointID: "c", AdvertisedCountry: "IR", MeasuredCountry: "TR", Source: "caller", Confidence: .4}}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Matches != 1 || p.Mismatches != 1 || p.Unknown != 1 {
		t.Fatalf("unexpected %+v", p)
	}
	if p.SelectionAuthority || p.PerformsGeoLookup || p.PerformsNetworkIO {
		t.Fatalf("authority leak %+v", p)
	}
}
