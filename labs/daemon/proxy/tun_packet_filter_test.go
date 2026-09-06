package proxy

import (
	"net"
	"testing"
)

func TestTUNPacketFilter(t *testing.T) {
	filter := NewTUNPacketFilter()

	// Configure VPN Subnet and Gateway
	_, subnet, _ := net.ParseCIDR("10.8.0.0/24")
	filter.VPNSubnet = subnet
	filter.GatewayIP = net.ParseIP("10.8.0.1")

	// 1. Verify standard allowed packet
	src := net.ParseIP("10.8.0.2")
	dst := net.ParseIP("8.8.8.8")
	if act := filter.Evaluate(src, dst, 443); act != TUNActionAllow {
		t.Errorf("expected ALLOW for standard traffic, got %v", act)
	}

	// 2. Verify blocked IP address rule
	filter.AddRule("192.168.1.100")
	srcBlocked := net.ParseIP("192.168.1.100")
	if act := filter.Evaluate(srcBlocked, dst, 80); act != TUNActionBlock {
		t.Errorf("expected BLOCK for blocked source IP, got %v", act)
	}
	if act := filter.Evaluate(dst, srcBlocked, 80); act != TUNActionBlock {
		t.Errorf("expected BLOCK for blocked destination IP, got %v", act)
	}

	// 3. Verify SMB/NetBIOS port blocks
	if act := filter.Evaluate(src, dst, 445); act != TUNActionBlock {
		t.Errorf("expected BLOCK for SMB port 445, got %v", act)
	}
	if act := filter.Evaluate(src, dst, 137); act != TUNActionBlock {
		t.Errorf("expected BLOCK for NetBIOS port 137, got %v", act)
	}

	// 4. Verify client isolation inside VPN subnet
	srcClient1 := net.ParseIP("10.8.0.2")
	srcClient2 := net.ParseIP("10.8.0.3")

	// Direct communication between client 1 and client 2 must be blocked
	if act := filter.Evaluate(srcClient1, srcClient2, 80); act != TUNActionBlock {
		t.Errorf("expected BLOCK for client-to-client isolation, got %v", act)
	}

	// Communication with gateway must be allowed
	if act := filter.Evaluate(srcClient1, filter.GatewayIP, 80); act != TUNActionAllow {
		t.Errorf("expected ALLOW for client-to-gateway traffic, got %v", act)
	}
	if act := filter.Evaluate(filter.GatewayIP, srcClient1, 80); act != TUNActionAllow {
		t.Errorf("expected ALLOW for gateway-to-client traffic, got %v", act)
	}

	// Communication between clients when isolation is disabled must be allowed
	filter.IsolateClients = false
	if act := filter.Evaluate(srcClient1, srcClient2, 80); act != TUNActionAllow {
		t.Errorf("expected ALLOW for client-to-client communication when isolation is disabled, got %v", act)
	}
}
