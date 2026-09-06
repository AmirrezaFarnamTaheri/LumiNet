package proxyconfig

import (
	"testing"
	"time"
)

func TestUpstreamMatrixSelection(t *testing.T) {
	matrix := NewUpstreamMatrix()

	matrix.RegisterNode(UpstreamNode{
		ID:       "node-1",
		Protocol: "vless",
		Endpoint: "1.1.1.1:443",
		Weight:   10,
		Latency:  150 * time.Millisecond,
		IsAlive:  true,
	})

	matrix.RegisterNode(UpstreamNode{
		ID:       "node-2",
		Protocol: "hysteria2",
		Endpoint: "2.2.2.2:443",
		Weight:   10,
		Latency:  45 * time.Millisecond,
		IsAlive:  true,
	})

	matrix.RegisterNode(UpstreamNode{
		ID:       "node-3",
		Protocol: "shadowsocks",
		Endpoint: "3.3.3.3:8388",
		Weight:   10,
		Latency:  10 * time.Millisecond,
		IsAlive:  false, // Dead
	})

	best, err := matrix.SelectBestNode()
	if err != nil {
		t.Fatalf("failed to select node: %v", err)
	}

	if best.ID != "node-2" {
		t.Errorf("expected node-2 (lowest latency alive), got %s", best.ID)
	}
}
