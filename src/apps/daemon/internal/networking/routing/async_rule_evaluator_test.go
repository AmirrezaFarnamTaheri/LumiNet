package routing

import (
	"net"
	"testing"
)

func TestAsyncRuleEvaluator(t *testing.T) {
	eval := NewAsyncRuleEvaluator("DIRECT")

	eval.AddRule(&RoutingRuleRecord{
		Type:           AsyncRuleDomainSuffix,
		Value:          "google.com",
		TargetOutbound: "PROXY_CLUSTER",
		Priority:       100,
	})

	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	eval.AddRule(&RoutingRuleRecord{
		Type:           AsyncRuleIPCIDR,
		IPNet:          ipNet,
		TargetOutbound: "INTERNAL_VPN",
		Priority:       80,
	})

	eval.AddRule(&RoutingRuleRecord{
		Type:           AsyncRulePortRange,
		PortStart:      8000,
		PortEnd:        9000,
		TargetOutbound: "DEV_OUTBOUND",
		Priority:       50,
	})

	// Test Suffix
	ctx1 := &RouteTrafficContext{
		Domain: "drive.google.com",
	}
	if eval.Evaluate(ctx1) != "PROXY_CLUSTER" {
		t.Fatalf("expected PROXY_CLUSTER for drive.google.com")
	}

	// Test CIDR
	ctx2 := &RouteTrafficContext{
		DestIP: net.ParseIP("10.50.1.2"),
	}
	if eval.Evaluate(ctx2) != "INTERNAL_VPN" {
		t.Fatalf("expected INTERNAL_VPN for 10.50.1.2")
	}

	// Test Port
	ctx3 := &RouteTrafficContext{
		DestPort: 8080,
	}
	if eval.Evaluate(ctx3) != "DEV_OUTBOUND" {
		t.Fatalf("expected DEV_OUTBOUND for port 8080")
	}

	// Test Default fallback
	ctx4 := &RouteTrafficContext{
		Domain:   "example.org",
		DestIP:   net.ParseIP("1.1.1.1"),
		DestPort: 443,
	}
	if eval.Evaluate(ctx4) != "DIRECT" {
		t.Fatalf("expected DIRECT default fallback")
	}
}
