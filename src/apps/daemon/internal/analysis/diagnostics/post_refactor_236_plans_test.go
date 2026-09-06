package diagnostics

import "testing"

func TestPostRefactor236ClientHelloNormalizesGREASEAndDetectsQUICGaps(t *testing.T) {
	p, err := BuildClientHelloEvidencePlan(ClientHelloEvidenceRequest{
		Transport: "quic", ServerName: "example.com", QUICVersion: 1,
		ExtensionIDs: []uint16{0, 0x0a0a, 43}, SupportedGroups: []uint16{29, 0x1a1a},
		Fragments: []QUICFragmentObservation{{Offset: 0, Length: 50}, {Offset: 60, Length: 20}}, CapturedBytes: 70,
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != "incomplete" || len(p.FragmentGaps) != 1 || p.NormalizedExtensionIDs[1] != 0x0a0a || p.NormalizedSupportedGroups[1] != 0x0a0a || p.FingerprintSHA256 == "" {
		t.Fatalf("unexpected clienthello plan: %+v", p)
	}
}

func TestPostRefactor236EncryptedDNSPreservesExistingECSAndBoundsTTL(t *testing.T) {
	p, err := BuildEncryptedDNSPolicyPlan(EncryptedDNSPolicyRequest{Transport: "odoh", PacketBytes: 257, ObservedTTL: 5, MinTTL: 30, MaxTTL: 3600, ErrorTTL: 60, PaddingBlockBytes: 128, ExistingECS: "203.0.113.0/24", RequestedECS: "198.51.100.0/24", CacheEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.EffectiveTTLSeconds != 30 || p.PaddedPacketBytes != 384 || p.ECSAction != "preserve-existing" || p.EffectiveECS != "203.0.113.0/24" || p.CacheState != "eligible" {
		t.Fatalf("unexpected encrypted DNS plan: %+v", p)
	}
}

func TestPostRefactor236TorLabCountsFailuresAndConsensus(t *testing.T) {
	p, err := BuildTorLabRelayPlan(TorLabRelayRequest{MinimumConsensusRelays: 2, AllowedFailures: 1, VerificationRounds: 3, Nodes: []TorLabNodeObservation{
		{ID: "auth", Role: "authority", Running: true, BootstrapPercent: 100, BandwidthKBPS: 1000, MetricsEnabled: true},
		{ID: "exit", Role: "exit", Running: true, BootstrapPercent: 100, BandwidthKBPS: 800, ExitAllowedPorts: []int{443, 80, 443}, Family: "f1"},
		{ID: "bridge", Role: "bridge", Running: false, BootstrapPercent: 60, Family: "f1"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != "degraded" || p.ConsensusRelays != 2 || p.ReadyNodes != 2 || len(p.FailedNodes) != 1 || len(p.ExitNodes["exit"]) != 2 {
		t.Fatalf("unexpected Tor lab plan: %+v", p)
	}
}

func TestPostRefactor236ProxyChainModesAreExplicit(t *testing.T) {
	hops := []ProxyChainHopObservation{{ID: "a", Protocol: "socks5", Reachable: true, SupportsIPv6: true}, {ID: "b", Protocol: "http", Reachable: false}, {ID: "c", Protocol: "socks5", Reachable: true, SupportsIPv6: true}}
	p, err := BuildProxyChainSafetyPlan(ProxyChainSafetyRequest{Mode: "dynamic", Hops: hops, ChainLength: 2, DestinationKind: "hostname", RemoteDNS: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != "ready" || len(p.Selected) != 2 || p.Selected[0] != "a" || p.Selected[1] != "c" || len(p.Skipped) != 1 {
		t.Fatalf("unexpected dynamic plan: %+v", p)
	}
	p, err = BuildProxyChainSafetyPlan(ProxyChainSafetyRequest{Mode: "strict", Hops: hops, ChainLength: 2, DestinationKind: "ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != "blocked" {
		t.Fatalf("strict chain must fail closed: %+v", p)
	}
	if _, err = BuildProxyChainSafetyPlan(ProxyChainSafetyRequest{Mode: "random", Hops: hops, ChainLength: 1, DestinationKind: "ipv4"}); err == nil {
		t.Fatal("random mode must require an explicit deterministic seed")
	}
}

func TestPostRefactor236ReplayScopesSaltByKeyAndAge(t *testing.T) {
	salt := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	p, err := BuildTransportReplayPlan(TransportReplayRequest{WindowCapacity: 2, MaxAgeSeconds: 60, Observations: []TransportReplayObservation{
		{KeyID: "a", SaltHex: salt, AgeSeconds: 1}, {KeyID: "a", SaltHex: salt, AgeSeconds: 2}, {KeyID: "b", SaltHex: salt, AgeSeconds: 2}, {KeyID: "c", SaltHex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", AgeSeconds: 90},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Accepted) != 2 || len(p.Replayed) != 1 || len(p.Stale) != 1 || p.Status != "degraded" {
		t.Fatalf("unexpected replay plan: %+v", p)
	}
}

func TestPostRefactor236SecretRefreshKeepsUnknownLookupClosed(t *testing.T) {
	p, err := BuildSecretRefreshPolicyPlan(SecretRefreshPolicyRequest{Name: "token", Declared: false, AllowLookup: false, PersistCache: true, CachedVersion: 2, RemoteVersion: 3, CacheAgeSeconds: 400, MaxCacheAgeSeconds: 300, PollIntervalSeconds: 100, PollJitterPct: 10, Watchers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if p.LookupAllowed || p.State != "stale" || !p.RefreshNeeded || p.NextPollMinSeconds != 90 || p.NextPollMaxSeconds != 111 || len(p.Warnings) < 2 {
		t.Fatalf("unexpected secret plan: %+v", p)
	}
}

func TestPostRefactor236RealityAdmissionRejectsMalformedShortIDs(t *testing.T) {
	p, err := BuildRealityAdmissionPlan(RealityAdmissionRequest{ServerNames: []string{"example.com"}, ShortIDs: []string{"a1b2", "xyz", "123"}, MaxTimeDiffSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != "partial" || len(p.ShortIDs) != 1 || p.ShortIDs[0] != "a1b2" || len(p.RejectedShortIDs) != 2 {
		t.Fatalf("unexpected REALITY plan: %+v", p)
	}
}

func TestPostRefactor236ServiceRecoveryRequiresValidatedRollbackPath(t *testing.T) {
	p, err := BuildServiceRecoveryPolicyPlan(ServiceRecoveryPolicyRequest{Service: "daemon", Operation: "update", BackupExists: false, RollbackAvailable: false, ConfigValidated: false, HealthAfter: "unknown", LogTailLines: 100})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != "blocked" || len(p.Warnings) != 2 {
		t.Fatalf("unexpected recovery plan: %+v", p)
	}
	p, err = BuildServiceRecoveryPolicyPlan(ServiceRecoveryPolicyRequest{Service: "daemon", Operation: "update", BackupExists: true, RollbackAvailable: true, ConfigValidated: true, HealthAfter: "unhealthy"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != "rollback-required" || len(p.RollbackSteps) != 3 {
		t.Fatalf("unhealthy post-change must propose rollback: %+v", p)
	}
}

func TestPostRefactor236NetworkTrustBundleDegradesConservatively(t *testing.T) {
	ch := ClientHelloEvidenceRequest{Transport: "quic", Fragments: []QUICFragmentObservation{{Offset: 10, Length: 10}}}
	reality := RealityAdmissionRequest{ServerNames: []string{"example.com"}, ShortIDs: []string{"a1b2"}}
	p, err := BuildNetworkTrustBundlePlan(NetworkTrustBundleRequest{ClientHello: &ch, Reality: &reality})
	if err != nil {
		t.Fatal(err)
	}
	if !p.ReadOnly || p.Status != "degraded" || len(p.Selected) != 2 || len(p.Warnings) != 1 {
		t.Fatalf("unexpected trust bundle: %+v", p)
	}
}
