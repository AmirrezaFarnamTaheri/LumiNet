package diagnostics

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPostRefactor225NetworkWorkflowOrdersTriggersCleanupAndRejectsExecution(t *testing.T) {
	plan, err := BuildNetworkWorkflowPlan([]NetworkWorkflowAction{
		{ID: "edge", Kind: "endpoint", Target: "tcp://edge.example:443"},
		{ID: "remote", Kind: "remote", Target: "remote.example:443", DependsOn: []string{"edge"}},
		{ID: "tunnel", Kind: "tunnel", Target: "remote", DependsOn: []string{"remote"}, Tail: true},
		{ID: "health-trigger", Kind: "child", Phase: "trigger", DependsOn: []string{"tunnel"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.InitOrder, ",") != "edge,remote,tunnel" || strings.Join(plan.TriggerOrder, ",") != "health-trigger" {
		t.Fatalf("unexpected order: %+v", plan)
	}
	if strings.Join(plan.CleanupOrder, ",") != "health-trigger,tunnel,remote,edge" || !plan.ReadOnly || plan.Executes {
		t.Fatalf("unexpected cleanup/authority: %+v", plan)
	}
	if _, err := BuildNetworkWorkflowPlan([]NetworkWorkflowAction{{ID: "danger", Kind: "docker-run", Target: "sh -c whoami"}}); err == nil {
		t.Fatal("host-executing workflow action admitted")
	}
	if _, err := BuildNetworkWorkflowPlan([]NetworkWorkflowAction{{ID: "a", Kind: "chain", DependsOn: []string{"b"}}, {ID: "b", Kind: "chain", DependsOn: []string{"a"}}}); err == nil {
		t.Fatal("workflow dependency cycle admitted")
	}
}

func TestPostRefactor225WireGuardPolicyOwnsExactPrefixesAndRequiresUnderLoadCookieGate(t *testing.T) {
	plan, err := BuildWireGuardDevicePolicyPlan(WireGuardDevicePolicyRequest{
		Peers: []WireGuardPolicyPeer{
			{ID: "default", PublicKey: "peer-a", AllowedIPs: []string{"0.0.0.0/0", "::/0"}},
			{ID: "corp", PublicKey: "peer-b", AllowedIPs: []string{"10.0.0.0/8"}, PersistentKeepaliveSeconds: 25},
		},
		UnderLoad: true, CookieGateEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ReplayWindowCounters != wireGuardReplayWindowCounters || plan.HandshakeRatePerSecond != 20 || plan.HandshakeBurst != 5 || !plan.ReadOnly {
		t.Fatalf("unexpected defaults: %+v", plan)
	}
	if plan.SessionLifecycle.RekeyAfterSeconds != 120 || plan.SessionLifecycle.RekeyAttemptSeconds != 90 || plan.SessionLifecycle.RekeyTimeoutSeconds != 5 || plan.SessionLifecycle.RejectAfterSeconds != 180 || plan.SessionLifecycle.KeepaliveTimeoutSeconds != 10 || plan.SessionLifecycle.CookieRefreshSeconds != 120 || plan.SessionLifecycle.MaxRetransmitHandshakes != 18 || plan.SessionLifecycle.ZeroKeyMaterialAfterSeconds != 540 || plan.SessionLifecycle.UnderLoadRetentionSeconds != 1 {
		t.Fatalf("wireguard session lifecycle drift: %+v", plan.SessionLifecycle)
	}
	if len(plan.Warnings) == 0 || !strings.Contains(plan.Warnings[0], "longest-prefix") {
		t.Fatalf("overlap visibility missing: %+v", plan)
	}
	if _, err := BuildWireGuardDevicePolicyPlan(WireGuardDevicePolicyRequest{
		Peers:     []WireGuardPolicyPeer{{ID: "a", PublicKey: "peer-a", AllowedIPs: []string{"0.0.0.0/0"}}},
		UnderLoad: true,
	}); err == nil {
		t.Fatal("under-load policy without cookie gate admitted")
	}
	if _, err := BuildWireGuardDevicePolicyPlan(WireGuardDevicePolicyRequest{
		Peers: []WireGuardPolicyPeer{
			{ID: "a", PublicKey: "peer-a", AllowedIPs: []string{"10.0.0.0/8"}},
			{ID: "b", PublicKey: "peer-b", AllowedIPs: []string{"10.0.0.0/8"}},
		},
	}); err == nil {
		t.Fatal("conflicting exact AllowedIP owners admitted")
	}
}

func TestPostRefactor226WireGuardReceiverIndexMappingsExpireAndStayIdentityBound(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	plan, err := BuildWireGuardDevicePolicyPlan(WireGuardDevicePolicyRequest{
		Peers:                 []WireGuardPolicyPeer{{ID: "peer", PublicKey: "pk", AllowedIPs: []string{"10.0.0.0/8"}}},
		AsOf:                  now,
		ReceiverIndexMappings: []WireGuardReceiverIndexMapping{{ReceiverIndex: 7, SourceIdentity: "198.51.100.7:51820", ExpiresAt: now.Add(2 * time.Minute)}},
		PacketObfuscation:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.ReceiverIndexMappings) != 1 || plan.ObfuscationClass != "traffic-shape-modification-only" {
		t.Fatalf("receiver-index/obfuscation policy lost: %+v", plan)
	}
	if _, err := BuildWireGuardDevicePolicyPlan(WireGuardDevicePolicyRequest{
		Peers:                 []WireGuardPolicyPeer{{ID: "peer", PublicKey: "pk", AllowedIPs: []string{"10.0.0.0/8"}}},
		AsOf:                  now,
		ReceiverIndexMappings: []WireGuardReceiverIndexMapping{{ReceiverIndex: 7, SourceIdentity: "", ExpiresAt: now.Add(time.Minute)}},
	}); err == nil {
		t.Fatal("receiver-index mapping without source identity admitted")
	}
	if _, err := BuildWireGuardDevicePolicyPlan(WireGuardDevicePolicyRequest{
		Peers:                 []WireGuardPolicyPeer{{ID: "peer", PublicKey: "pk", AllowedIPs: []string{"10.0.0.0/8"}}},
		AsOf:                  now,
		ReceiverIndexMappings: []WireGuardReceiverIndexMapping{{ReceiverIndex: 7, SourceIdentity: "src", ExpiresAt: now}},
	}); err == nil {
		t.Fatal("non-expiring receiver-index mapping admitted")
	}
}

func TestPostRefactor228WireGuardIndexTranslationRequiresRestartRevalidationAndMACRepair(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	plan, err := BuildWireGuardIndexTranslationPlan(WireGuardIndexTranslationRequest{
		AsOf:    now,
		Entries: []WireGuardIndexTranslationEntry{{SourceReceiverIndex: 7, TranslatedReceiverIndex: 7007, PeerIdentity: "peer-a", ExpiresAt: now.Add(2 * time.Minute), Persisted: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ReadOnly || plan.MutatesPackets || plan.RestoresMappings || !plan.MACRecomputeRequired || !reflect.DeepEqual(plan.PersistedNeedsRevalidation, []uint32{7}) {
		t.Fatalf("unexpected WireGuard translation plan: %+v", plan)
	}
	if _, err := BuildWireGuardIndexTranslationPlan(WireGuardIndexTranslationRequest{AsOf: now, Entries: []WireGuardIndexTranslationEntry{
		{SourceReceiverIndex: 7, TranslatedReceiverIndex: 7007, PeerIdentity: "peer-a", ExpiresAt: now.Add(time.Minute)},
		{SourceReceiverIndex: 8, TranslatedReceiverIndex: 7007, PeerIdentity: "peer-b", ExpiresAt: now.Add(time.Minute)},
	}}); err == nil {
		t.Fatal("duplicate translated receiver index admitted")
	}
	if _, err := BuildWireGuardIndexTranslationPlan(WireGuardIndexTranslationRequest{AsOf: now, Entries: []WireGuardIndexTranslationEntry{{SourceReceiverIndex: 7, TranslatedReceiverIndex: 8, PeerIdentity: "peer-a", ExpiresAt: now.Add(25 * time.Hour)}}}); err == nil {
		t.Fatal("unbounded WireGuard translation lifetime admitted")
	}
}
