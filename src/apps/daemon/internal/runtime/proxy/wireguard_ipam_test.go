package proxy

import (
	"strings"
	"testing"
)

func TestWireguardIpamAllocation(t *testing.T) {
	ipam, err := NewWireguardIpam("10.88.0.0/24", "fd00:88::/64")
	if err != nil {
		t.Fatalf("NewWireguardIpam error: %v", err)
	}

	peer1, err := ipam.AllocatePeer("pubkey111111111111111111111111111111111111=", "laptop")
	if err != nil {
		t.Fatalf("AllocatePeer failed: %v", err)
	}
	if peer1.AllocatedV4.String() != "10.88.0.2" {
		t.Errorf("expected 10.88.0.2, got %s", peer1.AllocatedV4.String())
	}

	conf := ipam.FormatClientConf(peer1, "clientPrivKey==", "vpn.example.com:51820", "srvPubKey==", "1.1.1.1")
	if !strings.Contains(conf, "Address = 10.88.0.2/32") {
		t.Errorf("conf mismatch: %s", conf)
	}
}
