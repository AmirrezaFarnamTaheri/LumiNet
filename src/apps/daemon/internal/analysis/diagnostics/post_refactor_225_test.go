package diagnostics

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func boolPtr225(v bool) *bool { return &v }

func TestPostRefactor225SNIPathRequiresResponseAndStrictTLS(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	plan, err := BuildSNIPathPlan(SNIPathPlanRequest{AsOf: now, ActivePoolSize: 1, Candidates: []SNIPathObservation{
		{IP: "203.0.113.1", SNI: "edge.example", TCPConnected: boolPtr225(true), TLSVerified: boolPtr225(true), FirstResponse: boolPtr225(false), Successes: 10, LatencyMs: 10, ObservedAt: now},
		{IP: "203.0.113.2", SNI: "edge.example", TCPConnected: boolPtr225(true), TLSVerified: boolPtr225(false), FirstResponse: boolPtr225(true), Successes: 10, LatencyMs: 5, ObservedAt: now},
		{IP: "203.0.113.3", SNI: "edge.example", TCPConnected: boolPtr225(true), TLSVerified: boolPtr225(true), FirstResponse: boolPtr225(true), Successes: 8, Failures: 1, LatencyMs: 30, ObservedAt: now, PathMTU: 1500},
		{IP: "203.0.113.4", SNI: "edge.example", TCPConnected: boolPtr225(true), TLSVerified: boolPtr225(true), PayloadBytes: 128, Successes: 7, Failures: 1, LatencyMs: 40, ObservedAt: now},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Active) != 1 || plan.Active[0] != "203.0.113.3|edge.example" {
		t.Fatalf("active=%v", plan.Active)
	}
	if len(plan.Reserve) != 1 || plan.Reserve[0] != "203.0.113.4|edge.example" {
		t.Fatalf("reserve=%v", plan.Reserve)
	}
	if plan.Ranked[0].RecommendedMaxSegmentPayloadBytes != 1460 {
		t.Fatalf("payload=%d", plan.Ranked[0].RecommendedMaxSegmentPayloadBytes)
	}
	for _, r := range plan.Ranked {
		if r.IP == "203.0.113.1" && r.Eligible {
			t.Fatal("connect-only evidence admitted")
		}
		if r.IP == "203.0.113.2" && r.Eligible {
			t.Fatal("unverified TLS admitted")
		}
	}
}

func TestPostRefactor225SNIPathDrainsStalePreviouslyActive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	plan, err := BuildSNIPathPlan(SNIPathPlanRequest{AsOf: now, MaxEvidenceAgeSeconds: 30, DrainTimeoutSeconds: 90, Candidates: []SNIPathObservation{{IP: "203.0.113.9", SNI: "edge.example", TCPConnected: boolPtr225(true), TLSVerified: boolPtr225(true), FirstResponse: boolPtr225(true), ObservedAt: now.Add(-time.Minute), PreviouslyActive: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Drain) != 1 || plan.Ranked[0].Recommendation != "drain" {
		t.Fatalf("plan=%+v", plan)
	}
	if !plan.Ranked[0].DrainUntil.Equal(now.Add(90 * time.Second)) {
		t.Fatalf("drain=%v", plan.Ranked[0].DrainUntil)
	}
}

func TestPostRefactor225TCPSequenceWraparound(t *testing.T) {
	if !TCPSeqAtOrAfter(2, ^uint32(0)-2) {
		t.Fatal("post-wrap sequence should be later")
	}
	if TCPSeqAtOrAfter(^uint32(0)-2, 2) {
		t.Fatal("pre-wrap sequence should be earlier")
	}
}

func TestPostRefactor225SegmentPayloadBounds(t *testing.T) {
	if got, err := RecommendMaxSegmentPayload(1500, 20, 32); err != nil || got != 1448 {
		t.Fatalf("got=%d err=%v", got, err)
	}
	if _, err := RecommendMaxSegmentPayload(500, 20, 20); err == nil {
		t.Fatal("accepted unsafe MTU")
	}
}

func TestPostRefactor225ArtifactAdmissionQuarantinesPrivateKeyWithoutEcho(t *testing.T) {
	secret := []byte("-----BEGIN PRIVATE KEY-----\nDO-NOT-ECHO\n-----END PRIVATE KEY-----")
	plan, err := BuildArtifactAdmissionPlan(ArtifactAdmissionRequest{ID: "mitm-ca", Kind: "certificate-bundle", ContentBase64: base64.StdEncoding.EncodeToString(secret)})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Quarantined || len(plan.DetectedSecretKinds) == 0 || plan.ContentReturned {
		t.Fatalf("plan=%+v", plan)
	}
	if strings.Contains(strings.Join(plan.Reasons, " "), "DO-NOT-ECHO") {
		t.Fatal("secret content leaked")
	}
}

func TestPostRefactor225ArtifactAdmissionChecksDigest(t *testing.T) {
	plan, err := BuildArtifactAdmissionPlan(ArtifactAdmissionRequest{ID: "rules", ExpectedSHA256: strings.Repeat("0", 64), ContentBase64: base64.StdEncoding.EncodeToString([]byte("rules"))})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Quarantined {
		t.Fatal("digest mismatch admitted")
	}
}

func TestPostRefactor225RelayInspectionRejectsUnsafeMITMPatterns(t *testing.T) {
	plan, err := BuildRelayInspectionPlan(RelayInspectionRequest{Transport: "starttls", TrustMode: "insecure", STARTTLSDetection: "magic-byte", MutationRequested: true, ScriptableMutation: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.AcceptedDesign || len(plan.Rejected) < 3 {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestPostRefactor225GatewayPlanReversibleAndConflictAware(t *testing.T) {
	plan, err := BuildSNIGatewayPlan(SNIGatewayPlanRequest{PublicIP: "203.0.113.8", RequirePublicIP: true, DNSPort: 53, TLSRouterPort: 443, HTTPRedirectPort: 80, DNSConfigured: true, TLSRouterConfigured: true, HTTPRedirectConfigured: true})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Ready || len(plan.ApplyOrder) == 0 || len(plan.RollbackOrder) == 0 {
		t.Fatalf("plan=%+v", plan)
	}
	bad, err := BuildSNIGatewayPlan(SNIGatewayPlanRequest{PublicIP: "127.0.0.1", RequirePublicIP: true, DNSPort: 53, TLSRouterPort: 53})
	if err != nil {
		t.Fatal(err)
	}
	if bad.Ready || len(bad.Conflicts) < 2 {
		t.Fatalf("bad=%+v", bad)
	}
}

func TestPostRefactor225DNSPolicyTruncationAndSecureFallback(t *testing.T) {
	plan, err := BuildDNSResolutionPolicyPlan(DNSResolutionPolicyRequest{PrimaryTransport: "udp", Strategy: "prefer-ipv6", CacheScope: "per-transport", RewriteTTLSeconds: 60, ResponseRejectionCache: true, Transports: []DNSPolicyTransport{{ID: "udp", Kind: "udp", Server: "1.1.1.1:53", TruncationFallbackTo: "tcp"}, {ID: "tcp", Kind: "tcp", Server: "1.1.1.1:53"}, {ID: "doh", Kind: "https", Server: "https://dns.example/dns-query"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.LookupFamilies) != 2 || plan.LookupFamilies[0] != "ipv6" {
		t.Fatalf("plan=%+v", plan)
	}
	_, err = BuildDNSResolutionPolicyPlan(DNSResolutionPolicyRequest{PrimaryTransport: "doh", RequireSecureTransport: true, Transports: []DNSPolicyTransport{{ID: "doh", Kind: "https", Server: "https://dns.example/dns-query", FallbackTo: "udp"}, {ID: "udp", Kind: "udp"}}})
	if err == nil {
		t.Fatal("secure-to-plaintext downgrade admitted")
	}
}

func TestPostRefactor225DNSPolicyRejectsTransportLoop(t *testing.T) {
	_, err := BuildDNSResolutionPolicyPlan(DNSResolutionPolicyRequest{PrimaryTransport: "a", Transports: []DNSPolicyTransport{{ID: "a", Kind: "udp", RouteThrough: "b"}, {ID: "b", Kind: "tcp", RouteThrough: "a"}}})
	if err == nil {
		t.Fatal("route loop admitted")
	}
}

func TestPostRefactor225MultiplexPolicyBoundsAndPayloadAccounting(t *testing.T) {
	plan, err := BuildMultiplexPolicyPlan(MultiplexPolicyRequest{Protocol: "smux", Version: 1, MaxConnections: 4, MaxStreamsPerConnection: 32, Padding: true, MaxPaddingBytes: 768})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.RuntimeSupported || plan.EstimatedMaxConcurrentStreams != 128 || len(plan.Invariants) == 0 {
		t.Fatalf("plan=%+v", plan)
	}
	if _, err := BuildMultiplexPolicyPlan(MultiplexPolicyRequest{Protocol: "smux", Padding: true, MaxPaddingBytes: 65535}); err == nil {
		t.Fatal("peer-sized padding admitted")
	}
}

func TestPostRefactor225RoutingArtifactRequiresDigestForRemote(t *testing.T) {
	_, err := BuildRoutingArtifactPlan([]RoutingArtifactCandidate{{ID: "geo", Kind: "geosite", Format: "srs", SourceURL: "https://example.test/geosite.srs", Bytes: 1234}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildRoutingArtifactPlan([]RoutingArtifactCandidate{{ID: "geo", Kind: "geosite", Format: "srs", SourceURL: "https://example.test/geosite.srs", ExpectedSHA256: strings.Repeat("a", 64), ActualSHA256: strings.Repeat("a", 64), Bytes: 1234, SourceVersion: "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Admitted) != 1 {
		t.Fatalf("plan=%+v", plan)
	}
	bad, err := BuildRoutingArtifactPlan([]RoutingArtifactCandidate{{ID: "geo", Kind: "geosite", Format: "srs", SourceURL: "https://example.test/geosite.srs", ExpectedSHA256: strings.Repeat("a", 64), ActualSHA256: strings.Repeat("b", 64), Bytes: 1234}})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad.Rejected) != 1 {
		t.Fatalf("bad=%+v", bad)
	}
}

func TestPostRefactor225TLSFingerprintPolicyReusesKnownGoodAndRejectsWeakCiphers(t *testing.T) {
	plan, err := BuildTLSFingerprintPolicyPlan(TLSFingerprintPolicyRequest{Candidates: []string{"chrome", "firefox", "randomized"}, KnownGood: "firefox", ReuseKnownGood: true, MaxTrials: 2, RequiredALPN: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.OrderedProfiles) != 2 || plan.OrderedProfiles[0] != "firefox" || !plan.ReuseKnownGood {
		t.Fatalf("plan=%+v", plan)
	}
	if _, err := BuildTLSFingerprintPolicyPlan(TLSFingerprintPolicyRequest{Candidates: []string{"chrome"}, AllowWeakCiphers: true}); err == nil {
		t.Fatal("weak ciphers admitted")
	}
	if _, err := BuildTLSFingerprintPolicyPlan(TLSFingerprintPolicyRequest{Candidates: []string{"chrome"}, QUICRequired: true, RequiredALPN: []string{"h2"}}); err == nil {
		t.Fatal("QUIC policy without h3 ALPN admitted")
	}
}

func TestPostRefactor225IncidentPolicyGraceMaintenanceRecoveryAndCooldown(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	plan, err := BuildServiceIncidentPolicyPlan(ServiceIncidentPolicyRequest{PreviousStatus: "up", CurrentStatus: "down", FailureStartedAt: now.Add(-2 * time.Minute), AsOf: now, NotificationGraceSeconds: 60, Maintenance: true, LastPersistedAt: now.Add(-10 * time.Second), WriteCooldownSeconds: 180})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Transition != "open" || plan.Notify || !plan.Persist {
		t.Fatalf("plan=%+v", plan)
	}
	recovery, err := BuildServiceIncidentPolicyPlan(ServiceIncidentPolicyRequest{PreviousStatus: "down", CurrentStatus: "up", IncidentOpen: true, FailureStartedAt: now.Add(-2 * time.Minute), AsOf: now, NotificationGraceSeconds: 60})
	if err != nil || recovery.Transition != "recover" || !recovery.Notify {
		t.Fatalf("recovery=%+v err=%v", recovery, err)
	}
	short, err := BuildServiceIncidentPolicyPlan(ServiceIncidentPolicyRequest{PreviousStatus: "down", CurrentStatus: "up", IncidentOpen: true, FailureStartedAt: now.Add(-20 * time.Second), AsOf: now, NotificationGraceSeconds: 60})
	if err != nil || short.Notify {
		t.Fatalf("short recovery should not notify: %+v err=%v", short, err)
	}
}

func TestPostRefactor225QueueBackpressureBoundsEvictionRestoreAndWireCount(t *testing.T) {
	plan, err := BuildQueueBackpressurePolicyPlan(QueueBackpressurePolicyRequest{Capacity: 10, CurrentDepth: 8, IncomingItems: 5, Strategy: "drop-oldest", MaxBatchItems: 4, AverageItemBytes: 100, MaxBatchBytes: 250, ExportFailed: true, ExportBatchItems: 2, RestoreOnExportFailure: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.EvictedOldest != 3 || plan.NewDepth != 10 || plan.BatchItems != 2 || plan.RestoreItems != 0 {
		t.Fatalf("plan=%+v", plan)
	}
	if _, err := BuildQueueBackpressurePolicyPlan(QueueBackpressurePolicyRequest{Capacity: 10, WireCount: 3, WirePayloadBytes: 10, MinWireItemBytes: 4}); err == nil {
		t.Fatal("malformed wire count admitted")
	}
}

func TestPostRefactor228SNIGatewayRejectsDeclaredUpstreamSelfLoopOffline(t *testing.T) {
	plan, err := BuildSNIGatewayPlan(SNIGatewayPlanRequest{PublicIP: "203.0.113.8", DNSPort: 53, TLSRouterPort: 443, DNSConfigured: true, TLSRouterConfigured: true, ListenerEndpoint: "0.0.0.0:40443", UpstreamEndpoint: "127.0.0.1:40443"})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.SelfLoop || plan.Ready {
		t.Fatalf("self-loop must block readiness: %+v", plan)
	}
	safe, err := BuildSNIGatewayPlan(SNIGatewayPlanRequest{PublicIP: "203.0.113.8", DNSPort: 53, TLSRouterPort: 443, DNSConfigured: true, TLSRouterConfigured: true, ListenerEndpoint: "127.0.0.1:40443", UpstreamEndpoint: "203.0.113.20:443"})
	if err != nil || safe.SelfLoop || !safe.Ready {
		t.Fatalf("remote upstream should remain admissible: %+v err=%v", safe, err)
	}
	if _, err := BuildSNIGatewayPlan(SNIGatewayPlanRequest{ListenerEndpoint: "127.0.0.1:40443", UpstreamEndpoint: "example.com:443"}); err == nil {
		t.Fatal("planner must not resolve hostnames or hide network I/O")
	}
}
