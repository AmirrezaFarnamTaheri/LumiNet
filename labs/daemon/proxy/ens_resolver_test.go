package proxy

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestResolveENS(t *testing.T) {
	// 1. Verify that invalid domains return errors immediately
	_, err := ResolveENS("google.com")
	if err == nil {
		t.Errorf("ResolveENS on google.com should have returned an error")
	}

	// 2. Perform a check on a real ENS name with net connection check
	// Ping cloudflare-eth.com to check for connectivity before running network-dependent test
	conn, err := net.DialTimeout("tcp", "cloudflare-eth.com:443", 2*time.Second)
	if err != nil {
		t.Skip("Skipping network-dependent ENS test: cloudflare-eth.com is unreachable")
		return
	}
	conn.Close()

	// Resolve vitalik.eth
	ips, err := ResolveENS("vitalik.eth")
	if err != nil {
		t.Fatalf("failed to resolve vitalik.eth: %v", err)
	}

	if len(ips) == 0 {
		t.Fatalf("expected resolved IP addresses for vitalik.eth, got none")
	}

	// Check if IP is in the Fake-IP range (198.18.x.x)
	resolvedIP := ips[0]
	if !strings.HasPrefix(resolvedIP, "198.18.") {
		t.Errorf("expected Fake-IP in 198.18.0.0/15 range, got %s", resolvedIP)
	}
}
