package transport

import (
	"net"
	"testing"
)

func TestNatTraversalTunnel(t *testing.T) {
	tunnel := NewNatTraversalTunnel("peer-local-01", P2PNatRestrictedCone)

	// Punch packet serialization test
	pkt := tunnel.CraftPunchPacket(42)
	seq, peerID, err := tunnel.ParsePunchPacket(pkt)
	if err != nil {
		t.Fatalf("failed to parse crafted punch packet: %v", err)
	}
	if seq != 42 || peerID != "peer-local-01" {
		t.Fatalf("unexpected parsed values: %d / %s", seq, peerID)
	}

	// Punchability checks
	if !CanDirectHolePunch(P2PNatFullCone, P2PNatSymmetric) {
		t.Fatalf("expected FullCone to Symmetric to be punchable")
	}
	if CanDirectHolePunch(P2PNatSymmetric, P2PNatSymmetric) {
		t.Fatalf("expected Symmetric to Symmetric to fail direct punch")
	}

	// State machine test
	cand := &PeerEndpointCandidate{
		PeerID:            "peer-remote-01",
		LocalEndpoint:     &net.UDPAddr{IP: net.ParseIP("192.168.1.5"), Port: 5000},
		ReflexiveEndpoint: &net.UDPAddr{IP: net.ParseIP("203.0.113.5"), Port: 5000},
		NatType:           P2PNatFullCone,
	}

	state := tunnel.InitiatePeerPunch(cand)
	if state != PunchStateProbing {
		t.Fatalf("expected Probing state, got %v", state)
	}

	if !tunnel.MarkEstablished("peer-remote-01") {
		t.Fatalf("failed to mark established")
	}
}
