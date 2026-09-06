package transport

import (
	"net"
	"testing"
)

func TestMultipathTunnelManager(t *testing.T) {
	mgr := NewMultipathTunnelManager("tun-go-01", BondingRoundRobin)

	addr1 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	addr2 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9002}
	remote := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}

	p1 := NewPathMetrics(1, addr1, remote, 10)
	p2 := NewPathMetrics(2, addr2, remote, 20)

	mgr.AddPath(p1)
	mgr.AddPath(p2)

	if len(mgr.ActivePaths()) != 2 {
		t.Fatalf("expected 2 active paths, got %d", len(mgr.ActivePaths()))
	}

	c1, err := mgr.SelectPathForEgress()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := mgr.SelectPathForEgress()
	if err != nil {
		t.Fatal(err)
	}
	if c1 == c2 {
		t.Errorf("round robin expected alternating paths, got %d and %d", c1, c2)
	}

	payload := []byte("go multipath payload")
	frame, err := mgr.Encapsulate(1, payload)
	if err != nil {
		t.Fatal(err)
	}

	rxID, dec, err := mgr.Decapsulate(frame)
	if err != nil {
		t.Fatal(err)
	}
	if rxID != 1 || string(dec) != string(payload) {
		t.Fatalf("payload mismatch, rxID: %d, dec: %s", rxID, string(dec))
	}
}
