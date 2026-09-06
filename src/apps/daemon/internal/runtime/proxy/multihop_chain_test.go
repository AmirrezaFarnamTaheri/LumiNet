package proxy

import (
	"testing"
)

func TestMultihopRelayChain(t *testing.T) {
	entry := RelayHopInfo{HopIndex: 0, Endpoint: "198.51.100.1:51820", PublicKey: "entryPub=="}
	exit := RelayHopInfo{HopIndex: 1, Endpoint: "198.51.100.2:51820", PublicKey: "exitPub=="}
	var psk [32]byte
	psk[0] = 0x42

	chain, err := NewMultihopRelayChain(entry, exit, psk)
	if err != nil {
		t.Fatalf("NewMultihopRelayChain failed: %v", err)
	}

	entryIps, exitIps := chain.NestedAllowedIPs()
	if entryIps != "10.64.0.1/32" || exitIps != "0.0.0.0/0, ::/0" {
		t.Fatalf("unexpected allowed IPs: %s, %s", entryIps, exitIps)
	}
}
