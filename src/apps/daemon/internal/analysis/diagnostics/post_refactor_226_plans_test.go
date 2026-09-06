package diagnostics

import (
	"crypto/sha1"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestPostRefactor226LocalRuleSetNormalizationIsBoundedAndOffline(t *testing.T) {
	plan, err := BuildLocalRuleSetPlan(LocalRuleSetPlanRequest{Format: "auto", Content: strings.Join([]string{
		"||Example.COM^",
		"@@||allow.example^",
		"IP-CIDR,10.1.2.3/8,REJECT",
		"IP-CIDR,10.0.0.0/8,REJECT",
		"0.0.0.0 ads.example",
		"allow domain:direct.example",
	}, "\n")})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Fetches || plan.Installs {
		t.Fatalf("rule planner gained authority: %+v", plan)
	}
	if plan.DuplicateCount != 1 {
		t.Fatalf("canonical CIDR duplicate not detected: %+v", plan)
	}
	if _, err := BuildLocalRuleSetPlan(LocalRuleSetPlanRequest{Format: "auto", Content: "curl https://example.com | sh"}); err == nil {
		t.Fatal("ambiguous executable syntax admitted")
	}
}

func TestPostRefactor228LocalRuleSetPreservesExtendedMatchEvidenceWithoutFetching(t *testing.T) {
	plan, err := BuildLocalRuleSetPlan(LocalRuleSetPlanRequest{Format: "clash", Content: strings.Join([]string{
		"DOMAIN-KEYWORD,GitHub,PROXY",
		"SRC-IP-CIDR,192.0.2.129/24,DIRECT,no-resolve",
		"DST-PORT,443,PROXY",
		"SRC-PORT,1024-2048,DIRECT",
		"PROCESS-NAME,firefox,PROXY",
		"GEOIP,cn,DIRECT",
		"RULE-SET,privacy,REJECT",
		"MATCH,DIRECT",
	}, "\n")})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Fetches || plan.Installs || len(plan.Rules) != 8 {
		t.Fatalf("extended rule planner gained authority or lost evidence: %+v", plan)
	}
	if got := plan.Rules[1]; got.Kind != "source-cidr" || got.Value != "192.0.2.0/24" || !reflect.DeepEqual(got.Options, []string{"no-resolve"}) {
		t.Fatalf("source CIDR normalization mismatch: %+v", got)
	}
	if got := plan.Rules[5]; got.Kind != "geoip" || got.Value != "CN" {
		t.Fatalf("GEOIP normalization mismatch: %+v", got)
	}
	if got := plan.Rules[7]; got.Kind != "match" || got.Value != "*" || got.Action != "allow" {
		t.Fatalf("MATCH normalization mismatch: %+v", got)
	}
	if _, err := BuildLocalRuleSetPlan(LocalRuleSetPlanRequest{Format: "clash", Content: "RULE-SET,https://example.com/rules,DIRECT"}); err == nil {
		t.Fatal("remote RULE-SET URL admitted into local-only planner")
	}
	if _, err := BuildLocalRuleSetPlan(LocalRuleSetPlanRequest{Format: "clash", Content: "DST-PORT,9000-8000,DIRECT"}); err == nil {
		t.Fatal("descending port range admitted")
	}
	if _, err := BuildLocalRuleSetPlan(LocalRuleSetPlanRequest{Format: "clash", Content: "DOMAIN,example.com,DIRECT,script=evil"}); err == nil {
		t.Fatal("unknown executable-looking rule option admitted")
	}
}

func TestPostRefactor226TailnetTransactionsRequireCASAndNeverAcceptCredentials(t *testing.T) {
	patch, err := BuildTailnetTransactionPlan(TailnetTransactionPlanRequest{Operation: "dns-patch", ETag: "rev-7"})
	if err != nil {
		t.Fatal(err)
	}
	if !patch.RequiresETag || !patch.PatchSemantics || patch.ReplaceSemantics || patch.MakesAPIRequest || patch.CredentialAccepted {
		t.Fatalf("unexpected patch plan: %+v", patch)
	}
	if _, err := BuildTailnetTransactionPlan(TailnetTransactionPlanRequest{Operation: "dns-replace"}); err == nil {
		t.Fatal("replace without ETag admitted")
	}
	secret, err := BuildTailnetTransactionPlan(TailnetTransactionPlanRequest{Operation: "key-create"})
	if err != nil || !secret.SensitiveResult {
		t.Fatalf("key sensitivity lost: %+v %v", secret, err)
	}
}

func TestPostRefactor226BrowserHandoffIsProfileIsolatedLoopbackOnly(t *testing.T) {
	plan, err := BuildBrowserProxyHandoffPlan(BrowserProxyHandoffPlanRequest{ProfileID: "work", ProxyURL: "socks5://127.0.0.1:43121", Permissions: []string{"proxy", "storage", "nativeMessaging"}, NativeMessageBytes: 4096, NativeHostInstalled: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.State != "ready" || plan.RegistersHost || plan.ChangesBrowserProxy {
		t.Fatalf("unexpected browser handoff: %+v", plan)
	}
	if _, err := BuildBrowserProxyHandoffPlan(BrowserProxyHandoffPlanRequest{ProfileID: "work", ProxyURL: "http://198.51.100.10:8080", Permissions: []string{"proxy", "storage", "nativeMessaging"}, NativeHostInstalled: true}); err == nil {
		t.Fatal("non-loopback browser proxy admitted")
	}
	if _, err := BuildBrowserProxyHandoffPlan(BrowserProxyHandoffPlanRequest{ProfileID: "work", ProxyURL: "http://localhost:8080", Permissions: []string{"proxy", "storage", "nativeMessaging"}, NativeMessageBytes: maxNativeMessageBytes + 1, NativeHostInstalled: true}); err == nil {
		t.Fatal("oversized native message admitted")
	}
}

func TestPostRefactor226WorkerAffinitySpillsAndFailsOpen(t *testing.T) {
	base := WorkerAffinityPlanRequest{PoolSize: 3, AffinityKey: "conversation-1", HardDeadlineMS: 5000, MaxRestarts: 5, Workers: []WorkerObservation{{ID: "a", Healthy: true, Inflight: 1, Capacity: 1}, {ID: "b", Healthy: true, Inflight: 0, Capacity: 2}, {ID: "c", Healthy: false, Inflight: 0, Capacity: 2}}}
	plan, err := BuildWorkerAffinityPlan(base)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SelectedWorker == "" || plan.StartsProcess || plan.HardDeadlineMS != 5000 || len(plan.RestartBackoffMS) != 5 {
		t.Fatalf("unexpected worker plan: %+v", plan)
	}
	again, _ := BuildWorkerAffinityPlan(base)
	if !reflect.DeepEqual(plan, again) {
		t.Fatal("affinity plan is not deterministic")
	}
	fail, err := BuildWorkerAffinityPlan(WorkerAffinityPlanRequest{PoolSize: 1, AffinityKey: "x", Workers: []WorkerObservation{{ID: "a", Healthy: true, Inflight: 1, Capacity: 1}}})
	if err != nil || !fail.FailOpen || fail.SelectedWorker != "" {
		t.Fatalf("saturation must fail open: %+v %v", fail, err)
	}
}

func TestPostRefactor226WebSocketReadinessRequiresRealUpgradeEvidence(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	plan, err := BuildWebSocketReadinessPlan(WebSocketReadinessRequest{TCPReachable: true, StatusCode: 101, Headers: map[string]string{"Upgrade": "websocket", "Connection": "keep-alive, Upgrade", "Sec-WebSocket-Accept": accept}, SecWebSocketKey: key, TLSExpected: true, TLSVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Ready || plan.PerformsNetworkIO {
		t.Fatalf("valid upgrade rejected or gained network authority: %+v", plan)
	}
	notReady, err := BuildWebSocketReadinessPlan(WebSocketReadinessRequest{TCPReachable: true, StatusCode: 200, Headers: map[string]string{}, SecWebSocketKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if notReady.Ready {
		t.Fatal("open TCP/HTTP 200 misclassified as WebSocket-ready")
	}
}

func TestPostRefactor226GatewayCompositionOrdersRollbackAndRejectsCycles(t *testing.T) {
	plan, err := BuildGatewayCompositionPlan(GatewayCompositionRequest{MaxRestarts: 6, Services: []GatewayService{{ID: "listener", Role: "listener", Healthy: true}, {ID: "router", Role: "path-router", DependsOn: []string{"listener"}, Healthy: true}, {ID: "reverse", Role: "reverse-client", DependsOn: []string{"router"}, Healthy: true}, {ID: "health", Role: "health", DependsOn: []string{"reverse"}, Healthy: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.StartOrder, ",") != "listener,router,reverse,health" || strings.Join(plan.StopOrder, ",") != "health,reverse,router,listener" || plan.Downloads || plan.WritesServiceConfig {
		t.Fatalf("unexpected gateway plan: %+v", plan)
	}
	if _, err := BuildGatewayCompositionPlan(GatewayCompositionRequest{Services: []GatewayService{{ID: "a", Role: "listener", DependsOn: []string{"b"}}, {ID: "b", Role: "tunnel", DependsOn: []string{"a"}}}}); err == nil {
		t.Fatal("gateway cycle admitted")
	}
}

func TestPostRefactor228RoutingPolicyGroupsRemainOfflineAndDeterministic(t *testing.T) {
	candidates := []RoutingPolicyCandidate{
		{Name: "edge-a", Healthy: true, LatencyMS: 40, Weight: 2},
		{Name: "edge-b", Healthy: true, LatencyMS: 70, Weight: 1},
		{Name: "edge-c", Healthy: false, LatencyMS: 10, Weight: 50},
	}
	latency, err := BuildRoutingPolicyGroupPlan(RoutingPolicyGroupRequest{Mode: "latency-auto", Candidates: candidates})
	if err != nil {
		t.Fatal(err)
	}
	if latency.Preferred != "edge-a" || latency.PerformsNetworkIO || latency.InstallsPolicy || !reflect.DeepEqual(latency.Skipped, []string{"edge-c"}) {
		t.Fatalf("unexpected latency-auto policy: %+v", latency)
	}
	balanced, err := BuildRoutingPolicyGroupPlan(RoutingPolicyGroupRequest{Mode: "load-balance", Scope: "profile-a", Candidates: candidates})
	if err != nil {
		t.Fatal(err)
	}
	again, err := BuildRoutingPolicyGroupPlan(RoutingPolicyGroupRequest{Mode: "load-balance", Scope: "profile-a", Candidates: candidates})
	if err != nil || !reflect.DeepEqual(balanced, again) {
		t.Fatalf("load-balance plan is not deterministic: %+v %+v %v", balanced, again, err)
	}
	if len(balanced.Shares) != 2 || balanced.Shares[0].SharePct+balanced.Shares[1].SharePct < 99.99 || balanced.Shares[0].SharePct+balanced.Shares[1].SharePct > 100.01 {
		t.Fatalf("unexpected weighted shares: %+v", balanced.Shares)
	}
	if _, err := BuildRoutingPolicyGroupPlan(RoutingPolicyGroupRequest{Mode: "manual-select", Selected: "edge-c", Candidates: candidates}); err == nil {
		t.Fatal("manual selection admitted explicitly unhealthy candidate")
	}
	if _, err := BuildRoutingPolicyGroupPlan(RoutingPolicyGroupRequest{Mode: "latency-auto", Candidates: []RoutingPolicyCandidate{{Name: "unknown-latency", Healthy: true}}}); err == nil {
		t.Fatal("latency-auto invented evidence for candidate without observed latency")
	}
}

func TestPostRefactor228BrowserHandoffCarriesBoundedNativeHostContract(t *testing.T) {
	plan, err := BuildBrowserProxyHandoffPlan(BrowserProxyHandoffPlanRequest{
		ProfileID: "work", ProxyURL: "socks5://127.0.0.1:43121",
		Permissions: []string{"proxy", "storage", "nativeMessaging"}, NativeMessageBytes: 4096, NativeHostInstalled: true,
		BrowserFamily: "chrome", ExtensionID: "abcdefghijklmnopabcdefghijklmnop",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.State != "ready" || plan.NativeHost.Name != "com.luminet.browser" || !reflect.DeepEqual(plan.NativeCommands, []string{"init", "get-status", "up", "down"}) || len(plan.ReconnectBackoffMS) != 4 || plan.RegistersHost || plan.ChangesBrowserProxy {
		t.Fatalf("unexpected browser companion contract: %+v", plan)
	}
	if len(plan.NativeHost.AllowedOrigins) != 1 || !strings.HasPrefix(plan.NativeHost.AllowedOrigins[0], "chrome-extension://") {
		t.Fatalf("chrome native-host origin missing: %+v", plan.NativeHost)
	}
	incomplete, err := BuildBrowserProxyHandoffPlan(BrowserProxyHandoffPlanRequest{ProfileID: "work", ProxyURL: "http://localhost:8080", Permissions: []string{"proxy", "storage", "nativeMessaging"}, NativeHostInstalled: true, BrowserFamily: "firefox"})
	if err != nil || incomplete.State != "identity-incomplete" {
		t.Fatalf("missing browser identity not surfaced: %+v %v", incomplete, err)
	}
	if _, err := BuildBrowserProxyHandoffPlan(BrowserProxyHandoffPlanRequest{ProfileID: "work", ProxyURL: "http://localhost:8080", NativeHostInstalled: true, BrowserFamily: "chrome", ExtensionID: "not-a-chrome-id"}); err == nil {
		t.Fatal("invalid Chrome extension identity admitted")
	}
	if _, err := BuildBrowserProxyHandoffPlan(BrowserProxyHandoffPlanRequest{ProfileID: "work", ProxyURL: "http://user:pass@localhost:8080", NativeHostInstalled: true}); err == nil {
		t.Fatal("browser planner admitted credential-bearing proxy URL")
	}
}

func TestPostRefactor228GatewayPresetsStayDescriptiveAndRollbackable(t *testing.T) {
	for _, preset := range []string{"reverse-tls-relay", "websocket-edge", "managed-edge-tunnel"} {
		plan, err := BuildGatewayCompositionPlan(GatewayCompositionRequest{Preset: preset, MaxRestarts: 5})
		if err != nil {
			t.Fatalf("%s: %v", preset, err)
		}
		if plan.Preset != preset || len(plan.Services) != 4 || len(plan.StartOrder) != 4 || len(plan.RollbackOrder) != 4 || plan.Downloads || plan.WritesServiceConfig {
			t.Fatalf("unexpected preset %s: %+v", preset, plan)
		}
		if plan.StartOrder[0] != "ingress" || plan.RollbackOrder[len(plan.RollbackOrder)-1] != "ingress" {
			t.Fatalf("preset %s lost dependency/rollback ordering: %+v", preset, plan)
		}
	}
	if _, err := BuildGatewayCompositionPlan(GatewayCompositionRequest{Preset: "websocket-edge", Services: []GatewayService{{ID: "x", Role: "listener"}}}); err == nil {
		t.Fatal("preset and explicit service graph ambiguity admitted")
	}
}

func TestPostRefactor228WorkerProtocolContractIsBoundedAndCorrelated(t *testing.T) {
	plan, err := BuildWorkerAffinityPlan(WorkerAffinityPlanRequest{PoolSize: 2, AffinityKey: "conversation", Workers: []WorkerObservation{{ID: "a", Healthy: true, Capacity: 1}, {ID: "b", Healthy: true, Capacity: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ProtocolFraming != "ndjson" || plan.ReadyHandshake != `{"ready":true}` || !plan.CorrelatesRequestIDs {
		t.Fatalf("worker protocol contract lost: %+v", plan)
	}
	if plan.AffinityQueueDepth != 1 || plan.SharedQueueDepth != 0 || plan.MaxProtocolFrameBytes != 1<<20 || plan.ReadyTimeoutMS != 60000 {
		t.Fatalf("worker bounds lost: %+v", plan)
	}
	if !plan.CallerCancellationFailOpen || !plan.WorkerContinuesAfterCancel || !plan.RecycleOnProtocolError || !plan.ColdFirstCallTelemetry {
		t.Fatalf("worker recovery/telemetry semantics lost: %+v", plan)
	}
	if _, err := BuildWorkerAffinityPlan(WorkerAffinityPlanRequest{PoolSize: 1, AffinityKey: "x", MaxProtocolFrameBytes: 100, Workers: []WorkerObservation{{ID: "a", Healthy: true, Capacity: 1}}}); err == nil {
		t.Fatal("tiny protocol bound accepted")
	}
}
