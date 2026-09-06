package routing

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestMeshWireguardCoordinator(t *testing.T) {
	coord := NewMeshWireguardCoordinator("local-node", net.ParseIP("100.64.0.1"))
	coord.RegisterDerpRelay(1, "derp-nyc.luminet.net")

	var pubKey [32]byte
	copy(pubKey[:], "test-key-32-bytes-long-12345678")

	peer := &MeshPeer{
		PeerID:           "remote-peer-1",
		PublicKey:        pubKey,
		VirtualIP:        net.ParseIP("100.64.0.2"),
		AllowedIPs:       []string{"10.20.0.0/16"},
		Endpoints:        []string{"203.0.113.10:51820"},
		DerpRegionID:     1,
		LastHandshakeTime: time.Now(),
		IsExitNode:       true,
	}

	coord.RegisterPeer(peer)

	// Test Route Lookup
	match := coord.LookupRoute(net.ParseIP("100.64.0.2"))
	if match != "remote-peer-1" {
		t.Fatalf("expected remote-peer-1, got %s", match)
	}

	matchSubnet := coord.LookupRoute(net.ParseIP("10.20.5.100"))
	if matchSubnet != "remote-peer-1" {
		t.Fatalf("expected remote-peer-1 for subnet, got %s", matchSubnet)
	}

	// Test Endpoint Selection
	mode, ep, err := coord.SelectBestEndpoint("remote-peer-1", time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != MeshModeDirect || ep != "203.0.113.10:51820" {
		t.Fatalf("expected direct mode with endpoint, got %v / %s", mode, ep)
	}

	// Old handshake -> DERP relay
	modeFallback, epFallback, err := coord.SelectBestEndpoint("remote-peer-1", time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modeFallback != MeshModeDerpRelay || epFallback != "derp-nyc.luminet.net" {
		t.Fatalf("expected DERP fallback, got %v / %s", modeFallback, epFallback)
	}

	// Test Config Generation
	cfg, err := coord.GeneratePeerConfig("remote-peer-1")
	if err != nil {
		t.Fatalf("failed to generate peer config: %v", err)
	}
	if !strings.Contains(cfg, "[Peer]") || !strings.Contains(cfg, "PersistentKeepalive = 25") {
		t.Fatalf("invalid generated config: %s", cfg)
	}
}
