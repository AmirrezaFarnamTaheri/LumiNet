package routing

import (
	"net"
	"testing"

	"github.com/maybeknott/luminet/internal/platform/security"
)

func TestIntelligentTrafficFilter(t *testing.T) {
	filter := NewIntelligentTrafficFilter("direct-egress")
	filter.DnsBlocklist.AddExactRule("bad-ads.net", security.CategoryAdvertising)
	filter.CanonicalRules.ParseRawRule("||blocked-portal.org")

	src := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51234}
	dst := &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 443}
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x20}

	v1 := filter.EvaluateTraffic(src, dst, "bad-ads.net", nil, payload)
	if v1.Type != VerdictBlockedDns || v1.Category != security.CategoryAdvertising {
		t.Fatalf("expected blocked ads, got %+v", v1)
	}

	v2 := filter.EvaluateTraffic(src, dst, "blocked-portal.org", nil, payload)
	if v2.Type != VerdictProxyRequired || v2.RuleHit != "blocked-portal.org" || v2.EgressTag != "tunnel-proxy" {
		t.Fatalf("expected proxy required, got %+v", v2)
	}

	v3 := filter.EvaluateTraffic(src, dst, "ok-site.org", nil, payload)
	if v3.Type != VerdictDirectPassThrough {
		t.Fatalf("expected direct pass through, got %+v", v3)
	}
}
