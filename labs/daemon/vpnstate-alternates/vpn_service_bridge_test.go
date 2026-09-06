package vpnstate

import "testing"

func TestStateLifecycle(t *testing.T) {
	b := NewVPNServiceBridge()
	want := VPNState{false, "tun0", "10.0.0.2", 1500}
	if b.GetState() != want {
		t.Fatalf("default=%#v", b.GetState())
	}
	b.UpdateState(true, "tun9", "10.1.0.2", 1400)
	got := b.GetState()
	if !got.IsConnected || got.InterfaceName != "tun9" || got.LocalIPv4 != "10.1.0.2" || got.MTU != 1400 {
		t.Fatalf("updated=%#v", got)
	}
}
