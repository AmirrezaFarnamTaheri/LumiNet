package mobilehost

import (
	"testing"
)

func TestMobileTunnelSupervisor(t *testing.T) {
	inc := map[string]struct{}{
		"com.android.chrome": {},
	}
	exc := map[string]struct{}{
		"com.bank.app": {},
	}

	cfg := MobileTunnelConfig{
		TunName:          "tun0",
		Mtu:              1500,
		IPv4Address:      "172.19.0.1",
		IPv4Netmask:      "255.255.255.0",
		DNSServers:       []string{"1.1.1.1"},
		IncludedPackages: inc,
		ExcludedPackages: exc,
	}

	sup := NewMobileTunnelSupervisor(cfg)
	if sup.State() != TunnelStopped {
		t.Fatalf("expected initial state stopped, got %v", sup.State())
	}

	if err := sup.Start(15); err != nil {
		t.Fatalf("unexpected start error: %v", err)
	}
	if sup.State() != TunnelRunning || sup.TunFd() != 15 {
		t.Fatalf("unexpected running state: %v, fd: %d", sup.State(), sup.TunFd())
	}

	if !sup.IsPackageRouted("com.android.chrome") {
		t.Fatalf("expected chrome to be routed")
	}
	if sup.IsPackageRouted("com.bank.app") {
		t.Fatalf("expected bank app to be excluded")
	}
	if sup.IsPackageRouted("com.other.app") {
		t.Fatalf("expected other app not routed when inclusion set non-empty")
	}

	sup.TriggerReconnect()
	if sup.State() != TunnelReconnecting || sup.ReconnectCount() != 1 {
		t.Fatalf("unexpected reconnect state: %v, count: %d", sup.State(), sup.ReconnectCount())
	}
}
