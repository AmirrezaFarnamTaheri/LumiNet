package diagnostics

import (
	"reflect"
	"strings"
	"testing"
)

func TestPostRefactor231PluggableTransportPlan(t *testing.T) {
	base := PluggableTransportPlanRequest{Transport: "obfs4", Platform: "linux", ObservedState: "stopped", StateDirConfigured: true, StateDirWritable: true}
	plan, err := BuildPluggableTransportPlan(base)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NextAction != "eligible-to-start" || plan.Ready {
		t.Fatalf("unexpected stopped plan: %+v", plan)
	}
	if !plan.SingletonRequired || !plan.StateDirRequired || plan.StartsTransport || plan.PerformsNetworkIO || plan.WritesState {
		t.Fatalf("authority invariant broken: %+v", plan)
	}

	missing := base
	missing.StateDirConfigured = false
	missing.StateDirWritable = false
	plan, err = BuildPluggableTransportPlan(missing)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NextAction != "configure-state-dir" || plan.Ready {
		t.Fatalf("missing state dir not blocked: %+v", plan)
	}

	unsafe := base
	unsafe.UnsafeLogging = true
	plan, err = BuildPluggableTransportPlan(unsafe)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SafeLogging || len(plan.Warnings) == 0 {
		t.Fatalf("unsafe logging warning missing: %+v", plan)
	}

	for _, transport := range []string{"snowflake", "dnstt"} {
		bad := base
		bad.Transport = transport
		bad.OutboundProxyKind = "socks5"
		if _, err := BuildPluggableTransportPlan(bad); err == nil {
			t.Fatalf("%s accepted unsupported outbound proxy", transport)
		}
	}

	listening := base
	listening.ObservedState = "listening"
	listening.LocalPort = 0
	if _, err := BuildPluggableTransportPlan(listening); err == nil {
		t.Fatal("listening state accepted zero local port")
	}
	listening.LocalPort = 39001
	plan, err = BuildPluggableTransportPlan(listening)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Ready || plan.NextAction != "hold" {
		t.Fatalf("listener evidence not admitted: %+v", plan)
	}

	snow := base
	snow.Transport = "snowflake"
	plan, err = BuildPluggableTransportPlan(snow)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NormalizedMaxPeers != 1 {
		t.Fatalf("default snowflake peers=%d", plan.NormalizedMaxPeers)
	}
	snow.MaxPeers = 65
	if _, err := BuildPluggableTransportPlan(snow); err == nil {
		t.Fatal("snowflake max peer bound not enforced")
	}

	invalidPeers := base
	invalidPeers.MaxPeers = 1
	if _, err := BuildPluggableTransportPlan(invalidPeers); err == nil {
		t.Fatal("non-snowflake accepted max_peers")
	}

	proxied := base
	proxied.OutboundProxyKind = "socks5"
	plan, err = BuildPluggableTransportPlan(proxied)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ProxySupported {
		t.Fatal("obfs4 unexpectedly reports no proxy support")
	}
}

func TestPostRefactor231CircumventionFallbackPlan(t *testing.T) {
	fresh := CircumventionFallbackRequest{Enabled: true, CurrentTransport: "direct", BootstrapProgress: 25, SecondsSinceProgress: 4, TimeoutSeconds: 30}
	plan, err := BuildCircumventionFallbackPlan(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != "wait" || !plan.ResetDeadline || plan.Terminal {
		t.Fatalf("fresh progress mishandled: %+v", plan)
	}
	if plan.MaximumTransitions != 3 || plan.PerformsNetworkIO || plan.StartsTransport || plan.MutatesPreferences {
		t.Fatalf("authority/bounds broken: %+v", plan)
	}

	complete := fresh
	complete.BootstrapProgress = 100
	plan, err = BuildCircumventionFallbackPlan(complete)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != "complete" || !plan.Terminal {
		t.Fatalf("complete bootstrap not terminal: %+v", plan)
	}

	disabled := fresh
	disabled.Enabled = false
	plan, err = BuildCircumventionFallbackPlan(disabled)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != "disabled" || !plan.Terminal {
		t.Fatalf("disabled flow not terminal: %+v", plan)
	}

	cases := []struct {
		current      string
		custom       bool
		next, action string
		terminal     bool
	}{
		{"direct", false, "snowflake", "fallback", false},
		{"snowflake", true, "custom", "fallback", false},
		{"snowflake", false, "obfs4", "fallback", false},
		{"custom", true, "obfs4", "fallback", false},
		{"obfs4", false, "", "fail", true},
		{"meek", false, "", "fail", true},
		{"webtunnel", false, "", "fail", true},
		{"dnstt", false, "", "fail", true},
	}
	for _, tc := range cases {
		req := CircumventionFallbackRequest{Enabled: true, CurrentTransport: tc.current, BootstrapProgress: 40, SecondsSinceProgress: 31, TimeoutSeconds: 30, CustomBridgesAvailable: tc.custom}
		got, err := BuildCircumventionFallbackPlan(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.current, err)
		}
		if got.NextTransport != tc.next || got.Action != tc.action || got.Terminal != tc.terminal {
			t.Fatalf("%s fallback mismatch: %+v", tc.current, got)
		}
	}
	if _, err := BuildCircumventionFallbackPlan(CircumventionFallbackRequest{Enabled: true, CurrentTransport: "direct", BootstrapProgress: 10, TimeoutSeconds: 4}); err == nil {
		t.Fatal("timeout lower bound not enforced")
	}
}

func TestPostRefactor231NaiveProxyPolicyPlan(t *testing.T) {
	req := NaiveProxyPolicyRequest{Platform: "linux", Listeners: []NaiveListenPolicy{{Scheme: "socks", Port: 1080}}, ProxyChain: []NaiveProxyHopPolicy{{Scheme: "https", HasAuth: true}}, Padding: "variant1", FastOpenRequested: true}
	plan, err := BuildNaiveProxyPolicyPlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.FirstPaddedFrames != 8 || plan.FrameHeaderBytes != 3 || plan.MaxPaddingBytes != 255 || plan.MaxPayloadBytes != 65535 {
		t.Fatalf("naive framing constants drifted: %+v", plan)
	}
	if plan.FirstConnectFastOpenAllowed || !plan.NaivePaddingEligible || !plan.PaddingNegotiatedByHeader {
		t.Fatalf("padding/fast-open contract drifted: %+v", plan)
	}
	if plan.PerformsNetworkIO || plan.StartsProxy || plan.WritesResolverRules {
		t.Fatalf("planner gained authority: %+v", plan)
	}
	if len(plan.Warnings) == 0 || !strings.Contains(strings.ToLower(strings.Join(plan.Warnings, " ")), "fast open") {
		t.Fatalf("first-connect fast-open warning missing: %+v", plan)
	}

	redir := req
	redir.Platform = "windows"
	redir.Listeners = []NaiveListenPolicy{{Scheme: "redir", Port: 1080}}
	if _, err := BuildNaiveProxyPolicyPlan(redir); err == nil {
		t.Fatal("redir accepted on windows")
	}
	socksAuth := req
	socksAuth.ProxyChain = []NaiveProxyHopPolicy{{Scheme: "socks", HasAuth: true}}
	if _, err := BuildNaiveProxyPolicyPlan(socksAuth); err == nil {
		t.Fatal("SOCKS auth admitted")
	}
	socksMulti := req
	socksMulti.ProxyChain = []NaiveProxyHopPolicy{{Scheme: "socks"}, {Scheme: "https"}}
	if _, err := BuildNaiveProxyPolicyPlan(socksMulti); err == nil {
		t.Fatal("multi-hop SOCKS chain admitted")
	}
	quicAfterTCP := req
	quicAfterTCP.ProxyChain = []NaiveProxyHopPolicy{{Scheme: "https"}, {Scheme: "quic"}}
	if _, err := BuildNaiveProxyPolicyPlan(quicAfterTCP); err == nil {
		t.Fatal("QUIC after TCP admitted")
	}
	ipv6 := req
	ipv6.ResolverCIDR = "2001:db8::/32"
	if _, err := BuildNaiveProxyPolicyPlan(ipv6); err == nil {
		t.Fatal("IPv6 resolver CIDR admitted")
	}
	badPadding := req
	badPadding.Padding = "variant2"
	if _, err := BuildNaiveProxyPolicyPlan(badPadding); err == nil {
		t.Fatal("unknown padding admitted")
	}
	finalSocks := req
	finalSocks.ProxyChain = []NaiveProxyHopPolicy{{Scheme: "socks"}}
	finalSocks.FastOpenRequested = false
	plan, err = BuildNaiveProxyPolicyPlan(finalSocks)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NaivePaddingEligible || len(plan.Warnings) == 0 {
		t.Fatalf("non-padding SOCKS final hop not surfaced: %+v", plan)
	}
}

func TestPostRefactor231StegoSchemePlan(t *testing.T) {
	candidates := []StegoSchemeCandidate{{Name: "cookie-transmit", Enabled: true, Usable: true, CapacityBytes: 1000}, {Name: "uri-transmit", Enabled: true, Usable: true, CapacityBytes: 500}, {Name: "json-post", Enabled: true, Usable: true, CapacityBytes: 1200}}
	req := StegoSchemePlanRequest{Direction: "client", PayloadBytes: 220, SelectionKey: "fixture", Candidates: candidates}
	plan, err := BuildStegoSchemePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Selected == nil || plan.Selected.Name != "uri-transmit" {
		t.Fatalf("small payload did not prefer URI: %+v", plan)
	}
	if plan.EmbedsPayload || plan.LoadsCoverAssets || plan.PerformsNetworkIO || plan.MutatesSchemeState {
		t.Fatalf("planner gained cover/runtime authority: %+v", plan)
	}

	noURI := req
	noURI.Candidates = append([]StegoSchemeCandidate(nil), candidates...)
	noURI.Candidates[1].Enabled = false
	plan, err = BuildStegoSchemePlan(noURI)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Selected == nil || plan.Selected.Name != "cookie-transmit" {
		t.Fatalf("cookie fallback missing: %+v", plan)
	}

	constrained := StegoSchemePlanRequest{Direction: "server", PayloadBytes: 800, SelectionKey: "x", Candidates: []StegoSchemeCandidate{{Name: "pdf-get", Enabled: true, Usable: true, CapacityBytes: 799}, {Name: "js-get", Enabled: true, Usable: true, CapacityBytes: 900, RecentFailures: 3}}}
	plan, err = BuildStegoSchemePlan(constrained)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Selected != nil || plan.Rejected["pdf-get"] != "insufficient-capacity" || plan.Rejected["js-get"] != "failure-threshold" {
		t.Fatalf("rejection semantics drifted: %+v", plan)
	}

	first, err := BuildStegoSchemePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildStegoSchemePlan(req)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.FallbackOrder, second.FallbackOrder) {
		t.Fatalf("selection is not deterministic: %#v != %#v", first.FallbackOrder, second.FallbackOrder)
	}

	dup := req
	dup.Candidates = []StegoSchemeCandidate{{Name: "raw-get", Enabled: true, Usable: true, CapacityBytes: 10}, {Name: "raw-get", Enabled: true, Usable: true, CapacityBytes: 10}}
	if _, err := BuildStegoSchemePlan(dup); err == nil {
		t.Fatal("duplicate scheme admitted")
	}
	invalid := req
	invalid.Candidates = []StegoSchemeCandidate{{Name: "unknown", Enabled: true, Usable: true, CapacityBytes: 1000}}
	if _, err := BuildStegoSchemePlan(invalid); err == nil {
		t.Fatal("unknown scheme admitted")
	}
}
