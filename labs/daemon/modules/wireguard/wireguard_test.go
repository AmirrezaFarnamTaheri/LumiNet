package wireguard

import (
	"strings"
	"testing"
)

func TestExcludeSubnetsIPv4(t *testing.T) {
	excludes := []string{"9.0.0.0/8", "10.0.0.0/8"}
	res := ExcludeSubnetsIPv4(excludes)

	if len(res) != 8 {
		t.Fatalf("expected 8 subnet divisions, got %d", len(res))
	}

	expectedSubnet := "8.0.0.0/8"
	found := false
	for _, s := range res {
		if s == expectedSubnet {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find subnet %s", expectedSubnet)
	}
}

func TestGenerateClientConfig_CustomAllowedIPs(t *testing.T) {
	c := &Config{
		ServerPublicKey: "srvkey123",
	}

	peer := PeerConfig{
		PrivateKey: "clihead123",
		IPAddress:  "10.0.0.2",
		AllowedIPs: []string{"192.168.1.0/24", "10.0.0.0/24"},
	}

	cfg := c.GenerateClientConfig(peer)
	if !strings.Contains(cfg, "AllowedIPs = 192.168.1.0/24, 10.0.0.0/24") {
		t.Errorf("GenerateClientConfig did not contain custom AllowedIPs: %s", cfg)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if len(priv) == 0 || len(pub) == 0 {
		t.Errorf("expected non-empty keys, got priv=%s pub=%s", priv, pub)
	}
}

func TestAddRemovePeer_Offline(t *testing.T) {
	// Attempting to add peer to a non-existent interface should return error
	err := AddPeer(false, "invalid_wg0", "pubkey123", "10.0.0.3/32")
	if err == nil {
		t.Errorf("expected error on invalid interface, got nil")
	}

	err = RemovePeer(false, "invalid_wg0", "pubkey123")
	if err == nil {
		t.Errorf("expected error on invalid interface, got nil")
	}
}
