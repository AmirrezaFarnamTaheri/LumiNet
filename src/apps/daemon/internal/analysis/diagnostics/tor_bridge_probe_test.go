package diagnostics

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestPlanTorBridgeProbeDirectAndFronted(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		line      string
		transport string
		host      string
		port      int
		fronted   bool
	}{
		{"direct", "obfs4 1.2.3.4:443 FINGER cert=x", "obfs4", "1.2.3.4", 443, false},
		{"prefix", "Bridge obfs4 [2001:67c:289c::9]:9001 FINGER cert=x", "obfs4", "2001:67c:289c::9", 9001, false},
		{"webtunnel-placeholder", "webtunnel [2001:db8::1]:443 F url=https://front.example/path", "webtunnel", "front.example", 443, true},
		{"dnstt-doh", "dnstt 192.0.2.4:1 F doh=https://dns.example/dns-query pubkey=x", "dnstt", "dns.example", 443, true},
		{"dnstt-dot", "dnstt 192.0.2.4:1 F dot=dot.example:8853 pubkey=x", "dnstt", "dot.example", 8853, true},
		{"snowflake-front", "snowflake 192.0.2.5:443 F fronts=cdn1.example,cdn2.example", "snowflake", "cdn1.example", 443, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := PlanTorBridgeProbe(tc.line)
			if err != nil {
				t.Fatal(err)
			}
			if got.Transport != tc.transport || got.Host != tc.host || got.Port != tc.port || got.Fronted != tc.fronted {
				t.Fatalf("plan=%+v, want transport=%s host=%s port=%d fronted=%v", got, tc.transport, tc.host, tc.port, tc.fronted)
			}
		})
	}
}

func TestPlanTorBridgeProbeFrontedRequiresRealFront(t *testing.T) {
	t.Parallel()
	if _, err := PlanTorBridgeProbe("webtunnel 192.0.2.1:443 F"); err == nil {
		t.Fatal("expected fronted placeholder without URL/front to fail")
	}
}

func TestResolvePublicBridgeTargetRefusesMixedDNSAnswers(t *testing.T) {
	t.Parallel()
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, err := resolvePublicBridgeTarget(context.Background(), "bridge.example", lookup); err == nil {
		t.Fatal("expected mixed public/private DNS result to fail closed")
	}
}

func TestResolvePublicBridgeTargetDedupesAndSorts(t *testing.T) {
	t.Parallel()
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}, nil
	}
	got, err := resolvePublicBridgeTarget(context.Background(), "bridge.example", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].String() != "1.1.1.1" || got[1].String() != "8.8.8.8" {
		t.Fatalf("unexpected addresses: %v", got)
	}
}

func TestProbeTorBridgesBoundsInput(t *testing.T) {
	t.Parallel()
	lines := make([]string, MaxTorBridgeProbeLines+1)
	_, err := probeTorBridgesWith(context.Background(), lines, 1, time.Second,
		func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("must not resolve")
		},
		nil,
	)
	if err == nil {
		t.Fatal("expected over-limit input to fail")
	}
}
