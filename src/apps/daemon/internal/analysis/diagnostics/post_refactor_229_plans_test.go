package diagnostics

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func boolPtr(value bool) *bool { return &value }

func TestTunnelSafetyFailsClosedOnCorruptPersistentIntent(t *testing.T) {
	plan, err := BuildTunnelSafetyPlan(TunnelSafetyRequest{
		DesiredState: "unsecured", ObservedState: "error", PersistedTargetState: "corrupt",
		LockdownMode: "auto", FirewallBlockApplied: boolPtr(false), ActionAfterDisconnect: "reconnect",
		ReconnectAttempt: 1, MaxReconnectAttempts: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DesiredState != "secured" || !plan.LockdownRequired || plan.EffectiveProtectionState != "degraded-unsafe" {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if !plan.ReconnectAllowed || plan.MutatesHostNetwork || !plan.ReadOnly {
		t.Fatalf("authority/reconnect truth lost: %+v", plan)
	}
}

func TestTunnelSafetyDoesNotCallFailedBlockSecure(t *testing.T) {
	plan, err := BuildTunnelSafetyPlan(TunnelSafetyRequest{DesiredState: "secured", ObservedState: "disconnected", LockdownMode: "always", FirewallBlockApplied: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if plan.EffectiveProtectionState == "secured-lockdown" || plan.FirewallBlockConfirmed {
		t.Fatalf("failed block misreported secure: %+v", plan)
	}
}

func TestTunnelSafetyRequiredLeakGuardsDegradeConnectedState(t *testing.T) {
	plan, err := BuildTunnelSafetyPlan(TunnelSafetyRequest{
		DesiredState:     "secured",
		ObservedState:    "connected",
		DNSGuardApplied:  boolPtr(true),
		QUICGuardApplied: boolPtr(true),
		RequiredGuards:   []string{"ipv6", "quic", "ipv6"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.EffectiveProtectionState != "degraded" || !reflect.DeepEqual(plan.RequiredGuards, []string{"ipv6", "quic"}) || !reflect.DeepEqual(plan.MissingOrFailedGuards, []string{"ipv6"}) {
		t.Fatalf("required guard truth lost: %+v", plan)
	}
}

func TestArtifactAdmissionRejectsHTMLMasqueradingAsZIP(t *testing.T) {
	html := []byte("<!DOCTYPE html><html><body>quota page</body></html>")
	plan, err := BuildArtifactAdmissionPlan(ArtifactAdmissionRequest{
		ID: "ezytel-wireguard", Filename: "ezytel_ConfigWireguard.zip", ContentBase64: base64.StdEncoding.EncodeToString(html),
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ClaimedFormat != "zip" || plan.DetectedFormat != "html" || !plan.FormatChecked || plan.FormatMatchesClaim || !plan.Quarantined {
		t.Fatalf("masquerading artifact not quarantined: %+v", plan)
	}
}

func TestTLSInterceptionEvidenceSeparatesMismatchGradeAndPFS(t *testing.T) {
	expectedPFS, observedPFS := true, false
	plan, err := BuildTLSInterceptionEvidencePlan(TLSInterceptionEvidenceRequest{
		Components:    []TLSInterceptionComponentEvidence{{Component: "cipher", Match: "possible"}, {Component: "extensions", Match: "impossible"}},
		ExpectedGrade: "B", ObservedGrade: "C", ExpectedPFS: &expectedPFS, ObservedPFS: &observedPFS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.WorstMatch != "impossible" || !plan.GradeRegressed || !plan.PFSLost || !plan.Suspicious || plan.UsesFingerprintDatabase || plan.IdentifiesInterceptionProduct || plan.PerformsNetworkIO || !plan.ReadOnly {
		t.Fatalf("TLS interception evidence truth lost: %+v", plan)
	}
	if !reflect.DeepEqual(plan.MismatchedComponents, []string{"extensions"}) {
		t.Fatalf("mismatches=%v", plan.MismatchedComponents)
	}
}

func TestSplitTunnelNormalizesAndHashesPortableIntent(t *testing.T) {
	req := SplitTunnelPlanRequest{Platform: "android", Mode: "exclude", Entries: []SplitTunnelEntry{{Kind: "package", Identifier: "com.example.alpha"}, {Kind: "package", Identifier: "com.example.alpha"}, {Kind: "process", Identifier: "browser"}}}
	first, err := BuildSplitTunnelPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSplitTunnelPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if first.DuplicateCount != 1 || len(first.Entries) != 2 || first.ManifestSHA256 != second.ManifestSHA256 {
		t.Fatalf("normalization not deterministic: %+v", first)
	}
	if first.RuntimeSupported || first.RuntimeEnforced || !first.RequiresRuntimeOwner || !first.ReadOnly {
		t.Fatalf("runtime truth lost: %+v", first)
	}
}

func TestSplitTunnelRejectsInertOrAmbiguousIntent(t *testing.T) {
	if _, err := BuildSplitTunnelPlan(SplitTunnelPlanRequest{Platform: "linux", Mode: "off", Entries: []SplitTunnelEntry{{Kind: "process", Identifier: "curl"}}}); err == nil {
		t.Fatal("off mode accepted entries")
	}
	if _, err := BuildSplitTunnelPlan(SplitTunnelPlanRequest{Platform: "linux", Mode: "include"}); err == nil {
		t.Fatal("include mode accepted empty entries")
	}
	if _, err := BuildSplitTunnelPlan(SplitTunnelPlanRequest{Platform: "linux", Mode: "include", Entries: []SplitTunnelEntry{{Kind: "path", Identifier: "a/../b"}}}); err == nil {
		t.Fatal("non-normalized path accepted")
	}
}

func TestRelayConstraintsSeparateEligibilityFromScoring(t *testing.T) {
	req := RelayConstraintPlanRequest{
		Mode: "multihop",
		Candidates: []RelayConstraintCandidate{
			{ID: "se-entry", Country: "se", City: "sto", Provider: "p1", Owned: true, Active: true, IPVersions: []string{"4", "6"}, Ports: []int{443}, Features: []string{"daita"}, Obfuscation: []string{"quic", "udp2tcp"}},
			{ID: "us-exit", Country: "us", City: "nyc", Provider: "p2", Owned: false, Active: true, IPVersions: []string{"4"}, Ports: []int{51820}},
			{ID: "dead", Country: "us", Provider: "p2", Active: false, IPVersions: []string{"4"}},
		},
		Entry: RelayConstraints{Country: "se", Ownership: "owned", IPVersion: "6", Port: 443, RequiredFeatures: []string{"daita"}, Obfuscation: "quic"},
		Exit:  RelayConstraints{Country: "us", Providers: []string{"p2"}, Ownership: "rented", IPVersion: "4"},
	}
	plan, err := BuildRelayConstraintPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SuggestedEntry != "se-entry" || plan.SuggestedExit != "us-exit" {
		t.Fatalf("unexpected pair: %+v", plan)
	}
	if !plan.RequiresEndpointScoring || plan.PerformsNetworkIO || plan.InstallsTunnel || !plan.ReadOnly {
		t.Fatalf("authority split: %+v", plan)
	}
	if len(plan.RejectedExit) == 0 {
		t.Fatal("rejection reasons not preserved")
	}
}

func TestRelayAutohopPrefersValidSinglehop(t *testing.T) {
	plan, err := BuildRelayConstraintPlan(RelayConstraintPlanRequest{Mode: "autohop", Candidates: []RelayConstraintCandidate{{ID: "a", Active: true, IPVersions: []string{"4"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.AutohopUsesMultihop || plan.SuggestedExit != "a" {
		t.Fatalf("autohop failed to retain valid singlehop: %+v", plan)
	}
}

func TestRelayMultihopNeverUsesSameIdentityTwice(t *testing.T) {
	plan, err := BuildRelayConstraintPlan(RelayConstraintPlanRequest{Mode: "multihop", Candidates: []RelayConstraintCandidate{{ID: "only", Active: true, IPVersions: []string{"4"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.SuggestedEntry != "" || plan.SuggestedExit != "" {
		t.Fatalf("same relay selected twice: %+v", plan)
	}
}

func TestUpdateRolloutDeterministicAndReplayAware(t *testing.T) {
	req := UpdateRolloutPlanRequest{Version: "229.0.0", Rollout: 0.5, CohortSeed: 42, MetadataSequence: 11, HighestSeenSequence: 10}
	first, err := BuildUpdateRolloutPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildUpdateRolloutPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if first.CohortThreshold != second.CohortThreshold || first.CohortThreshold <= 0 || first.CohortThreshold > 1 {
		t.Fatalf("unstable threshold: %+v", first)
	}
	if !first.SequenceFresh || first.MetadataReplayRejected || first.PersistsHighWaterMark || !first.RequiresPersistedHighWaterMark {
		t.Fatalf("sequence authority truth lost: %+v", first)
	}
}

func TestUpdateRolloutRejectsStaleAndWithdrawn(t *testing.T) {
	stale, err := BuildUpdateRolloutPlan(UpdateRolloutPlanRequest{Version: "229", Rollout: 1, CohortSeed: 1, MetadataSequence: 9, HighestSeenSequence: 10})
	if err != nil {
		t.Fatal(err)
	}
	if stale.Eligible || !stale.MetadataReplayRejected {
		t.Fatalf("stale metadata became eligible: %+v", stale)
	}
	withdrawn, err := BuildUpdateRolloutPlan(UpdateRolloutPlanRequest{Version: "229", Rollout: 0, CohortSeed: 1, MetadataSequence: 10, HighestSeenSequence: 10})
	if err != nil {
		t.Fatal(err)
	}
	if withdrawn.Eligible || !withdrawn.Withdrawn {
		t.Fatalf("zero rollout not withdrawn: %+v", withdrawn)
	}
}

func Test229PlannerInvariantsStateNoHiddenAuthority(t *testing.T) {
	tunnel, _ := BuildTunnelSafetyPlan(TunnelSafetyRequest{DesiredState: "unsecured", ObservedState: "disconnected"})
	split, _ := BuildSplitTunnelPlan(SplitTunnelPlanRequest{Platform: "android", Mode: "off"})
	relay, _ := BuildRelayConstraintPlan(RelayConstraintPlanRequest{Candidates: []RelayConstraintCandidate{{ID: "r", Active: true}}})
	update, _ := BuildUpdateRolloutPlan(UpdateRolloutPlanRequest{Version: "v", Rollout: 1, MetadataSequence: 1})
	joined := strings.Join(append(append(append(tunnel.Invariants, split.Invariants...), relay.Invariants...), update.Invariants...), "\n")
	for _, needle := range []string{"never changes firewall", "does not install drivers", "performs no remote probe", "installs no update"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("missing non-authority invariant %q", needle)
		}
	}
}

func TestWireGuardEphemeralPeerTimeoutBackoffIsCapped(t *testing.T) {
	peer := WireGuardPolicyPeer{ID: "peer", PublicKey: "pubkey", AllowedIPs: []string{"0.0.0.0/0"}}
	for attempt, want := range map[int]int{0: 8, 1: 16, 2: 32, 3: 48, 8: 48} {
		plan, err := BuildWireGuardDevicePolicyPlan(WireGuardDevicePolicyRequest{Peers: []WireGuardPolicyPeer{peer}, EphemeralPeerRetryAttempt: attempt})
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if plan.EphemeralPeerTimeoutSeconds != want {
			t.Fatalf("attempt %d timeout=%d want=%d", attempt, plan.EphemeralPeerTimeoutSeconds, want)
		}
		if (attempt >= 3) != plan.EphemeralPeerTimeoutCapped {
			t.Fatalf("attempt %d capped=%v", attempt, plan.EphemeralPeerTimeoutCapped)
		}
	}
	if _, err := BuildWireGuardDevicePolicyPlan(WireGuardDevicePolicyRequest{Peers: []WireGuardPolicyPeer{peer}, EphemeralPeerRetryAttempt: 17}); err == nil {
		t.Fatal("unbounded retry attempt accepted")
	}
}
