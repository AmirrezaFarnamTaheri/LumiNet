package security

import (
	"strings"
	"testing"
)

func TestWireguardIpamManager(t *testing.T) {
	mgr, err := NewWireguardIpamManager("10.88.0", 51820)
	if err != nil {
		t.Fatalf("failed to create ipam manager: %v", err)
	}

	p1, err := mgr.AllocatePeer("pubkey11111111111111111111111111=")
	if err != nil {
		t.Fatalf("allocate p1 failed: %v", err)
	}
	if p1.AssignedIP != "10.88.0.2" {
		t.Errorf("expected 10.88.0.2, got %s", p1.AssignedIP)
	}

	p2, err := mgr.AllocatePeer("pubkey22222222222222222222222222=")
	if err != nil {
		t.Fatalf("allocate p2 failed: %v", err)
	}
	if p2.AssignedIP != "10.88.0.3" {
		t.Errorf("expected 10.88.0.3, got %s", p2.AssignedIP)
	}

	serverCfg := mgr.GenerateServerConfig("privkey_srv=")
	if !strings.Contains(serverCfg, "Address = 10.88.0.1/24") || !strings.Contains(serverCfg, "pubkey11111111111111111111111111=") {
		t.Fatalf("server config missing expected lines")
	}

	clientCfg, err := mgr.GenerateClientConfig(
		"pubkey11111111111111111111111111=",
		"privkey_cli=",
		"pubkey_srv=",
		"1.2.3.4:51820",
	)
	if err != nil {
		t.Fatalf("generate client config failed: %v", err)
	}
	if !strings.Contains(clientCfg, "Address = 10.88.0.2/32") {
		t.Fatalf("client config missing assigned IP")
	}

	err = mgr.ReleasePeer("pubkey11111111111111111111111111=")
	if err != nil {
		t.Fatalf("release peer failed: %v", err)
	}
}
