package proxyconfig

import (
	"testing"
)

func TestPublicRelayAggregator(t *testing.T) {
	agg := NewPublicRelayAggregator()

	n1 := PublicRelayNode{
		NodeID:      "node-us-ss",
		Protocol:    "shadowsocks",
		Host:        "198.51.100.20",
		Port:        8388,
		CountryCode: "US",
		PingMs:      50,
		UptimeRatio: 0.99,
		IsAlive:     true,
	}

	n2 := PublicRelayNode{
		NodeID:      "node-de-vless",
		Protocol:    "vless",
		Host:        "198.51.100.21",
		Port:        443,
		CountryCode: "DE",
		PingMs:      30,
		UptimeRatio: 0.95,
		IsAlive:     true,
	}

	n3 := PublicRelayNode{
		NodeID:      "node-us-vless",
		Protocol:    "vless",
		Host:        "198.51.100.22",
		Port:        443,
		CountryCode: "US",
		PingMs:      20,
		UptimeRatio: 0.98,
		IsAlive:     true,
	}

	_ = agg.IngestNode(n1)
	_ = agg.IngestNode(n2)
	_ = agg.IngestNode(n3)

	if agg.TotalCount() != 3 {
		t.Fatalf("expected 3 nodes, got %d", agg.TotalCount())
	}

	// Filter US nodes, sorted by ping
	usNodes := agg.QueryRelays("US", "", 10)
	if len(usNodes) != 2 {
		t.Fatalf("expected 2 US nodes, got %d", len(usNodes))
	}
	if usNodes[0].NodeID != "node-us-vless" { // 20ms < 50ms
		t.Fatalf("expected lower ping node first, got %s", usNodes[0].NodeID)
	}

	// Update health
	agg.UpdateHealth("node-us-vless", 999, false)
	usNodesAfter := agg.QueryRelays("US", "", 10)
	if len(usNodesAfter) != 1 {
		t.Fatalf("expected 1 alive US node after down update")
	}
}
