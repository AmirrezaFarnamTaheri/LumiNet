package routing

import (
	"net"
	"testing"
)

func TestSplitTunnelRuleSync(t *testing.T) {
	sync := NewSplitTunnelRuleSync(ActionBypassVPN)

	// 10.0.0.0/8 routes via VPN
	if err := sync.AddRule("rule-1", "10.0.0.0/8", ActionRouteThroughVPN, 10); err != nil {
		t.Fatalf("failed to add rule 1: %v", err)
	}

	// 10.1.2.0/24 bypasses VPN (more specific)
	if err := sync.AddRule("rule-2", "10.1.2.0/24", ActionBypassVPN, 10); err != nil {
		t.Fatalf("failed to add rule 2: %v", err)
	}

	// Test LPM
	res1 := sync.MatchIP(net.ParseIP("10.1.2.55"))
	if res1 != ActionBypassVPN {
		t.Fatalf("expected BypassVPN for 10.1.2.55, got %v", res1)
	}

	res2 := sync.MatchIP(net.ParseIP("10.5.0.1"))
	if res2 != ActionRouteThroughVPN {
		t.Fatalf("expected RouteThroughVPN for 10.5.0.1, got %v", res2)
	}

	resDefault := sync.MatchIP(net.ParseIP("192.168.1.1"))
	if resDefault != ActionBypassVPN {
		t.Fatalf("expected default BypassVPN for 192.168.1.1, got %v", resDefault)
	}

	// Test feed import
	feed := "# Comments\n172.16.0.0/12\n198.51.100.0/24\n"
	imported := sync.SyncFromFeed(feed, ActionRouteThroughVPN)
	if imported != 2 {
		t.Fatalf("expected 2 rules imported, got %d", imported)
	}
	if sync.MatchIP(net.ParseIP("172.20.0.1")) != ActionRouteThroughVPN {
		t.Fatalf("expected imported CIDR to route via VPN")
	}
}
