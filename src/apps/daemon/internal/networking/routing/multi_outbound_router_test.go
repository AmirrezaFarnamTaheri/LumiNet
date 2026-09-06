package routing

import (
	"testing"
)

func TestMultiOutboundRouter(t *testing.T) {
	router := NewMultiOutboundRouter(OutboundPolicy{Type: PolicyDirect})
	router.AddRule("internal.corp", true, OutboundPolicy{Type: PolicyDirect})
	router.AddRule("blocked-site.com", false, OutboundPolicy{Type: PolicyProxy, Tag: "us-node-1"})
	router.AddRule("malware.net", true, OutboundPolicy{Type: PolicyReject})

	p1 := router.MatchTarget("app.internal.corp")
	if p1.Type != PolicyDirect {
		t.Fatalf("expected direct, got %v", p1)
	}

	p2 := router.MatchTarget("blocked-site.com")
	if p2.Type != PolicyProxy || p2.Tag != "us-node-1" {
		t.Fatalf("expected proxy us-node-1, got %v", p2)
	}

	p3 := router.MatchTarget("sub.malware.net")
	if p3.Type != PolicyReject {
		t.Fatalf("expected reject, got %v", p3)
	}

	p4 := router.MatchTarget("random-domain.io")
	if p4.Type != PolicyDirect {
		t.Fatalf("expected direct, got %v", p4)
	}

	outbounds := []string{"node-a", "node-b", "node-c"}
	sel1, ok1 := router.SelectBalancedOutbound(outbounds)
	sel2, ok2 := router.SelectBalancedOutbound(outbounds)
	if !ok1 || !ok2 || sel1 == sel2 {
		t.Fatalf("expected round robin distribution, got %s and %s", sel1, sel2)
	}
}
