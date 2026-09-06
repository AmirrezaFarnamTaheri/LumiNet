package proxy

import (
	"net"
	"testing"
)

func TestGoCidrCalculations(t *testing.T) {
	_, baseNet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("failed to parse test CIDR: %v", err)
	}

	// 1. Subnet division test
	sub, err := Subnet(baseNet, 4, 2) // split /24 into /28s, get index 2
	if err != nil {
		t.Fatalf("Subnet failed: %v", err)
	}
	expectedSub := "192.168.1.32/28"
	if sub.String() != expectedSub {
		t.Errorf("expected Subnet to be %q, got %q", expectedSub, sub.String())
	}

	// 2. Host lookup test
	host, err := Host(baseNet, 15)
	if err != nil {
		t.Fatalf("Host failed: %v", err)
	}
	expectedHost := "192.168.1.15"
	if host.String() != expectedHost {
		t.Errorf("expected Host to be %q, got %q", expectedHost, host.String())
	}

	// 3. Address range test
	first, last := AddressRange(baseNet)
	if first.String() != "192.168.1.0" {
		t.Errorf("expected first address to be 192.168.1.0, got %s", first.String())
	}
	if last.String() != "192.168.1.255" {
		t.Errorf("expected last address to be 192.168.1.255, got %s", last.String())
	}

	// 4. Overlap verification test
	_, otherNet, _ := net.ParseCIDR("192.168.1.128/25")
	err = VerifyNoOverlap([]*net.IPNet{baseNet}, otherNet)
	if err == nil {
		t.Error("expected overlap error for overlapping networks")
	}

	// 5. Next/Previous Subnet test
	next, ok := NextSubnet(baseNet, 24)
	if !ok || next.String() != "192.168.2.0/24" {
		t.Errorf("expected next subnet to be 192.168.2.0/24, got %v (ok=%t)", next, ok)
	}

	prev, ok := PreviousSubnet(baseNet, 24)
	if !ok || prev.String() != "192.168.0.0/24" {
		t.Errorf("expected previous subnet to be 192.168.0.0/24, got %v (ok=%t)", prev, ok)
	}
}
