package security

import (
	"testing"
)

func TestLeakGuardSupervisor(t *testing.T) {
	sup := NewLeakGuardSupervisor("tun0", []string{"10.0.0.1"}, true)

	// Tunnel traffic allowed
	if !sup.ValidateOutboundDestination("8.8.8.8", 53, "tun0") {
		t.Fatalf("tunnel DNS traffic should be allowed")
	}

	// External physical adapter sending unapproved DNS -> blocked
	if sup.ValidateOutboundDestination("192.168.1.1", 53, "eth0") {
		t.Fatalf("external unapproved DNS should be blocked")
	}
	if sup.TotalLeaksDetected() != 1 {
		t.Fatalf("expected 1 leak detected")
	}

	// External IPv6 -> blocked
	if sup.ValidateOutboundDestination("2001:db8::1", 443, "eth0") {
		t.Fatalf("external IPv6 should be blocked")
	}
	if sup.TotalLeaksDetected() != 2 {
		t.Fatalf("expected 2 leaks detected")
	}

	// Disable killswitch
	sup.SetKillswitch(false)
	if !sup.ValidateOutboundDestination("192.168.1.1", 53, "eth0") {
		t.Fatalf("traffic should be permitted with killswitch disabled")
	}
}
