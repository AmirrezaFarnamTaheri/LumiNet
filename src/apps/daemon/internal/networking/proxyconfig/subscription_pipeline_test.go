package proxyconfig

import (
	"encoding/base64"
	"testing"
)

func TestIngestSubscriptionPlaintext(t *testing.T) {
	raw := `
vless://uuid-1@1.1.1.1:443?security=reality#EdgeNode1
vmess://base64config#EdgeNode2
# commented node
vless://uuid-1@1.1.1.1:443?security=reality#EdgeNode1
`
	nodes, err := IngestSubscription(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(nodes) != 2 {
		t.Fatalf("expected 2 unique nodes, got %d", len(nodes))
	}
	if nodes[0].Protocol != "vless" {
		t.Errorf("expected protocol vless, got %s", nodes[0].Protocol)
	}
	if nodes[0].Tag != "EdgeNode1" {
		t.Errorf("expected tag EdgeNode1, got %s", nodes[0].Tag)
	}
}

func TestIngestSubscriptionBase64(t *testing.T) {
	raw := "trojan://pass@example.com:443#TrojanNode"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	nodes, err := IngestSubscription(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].Protocol != "trojan" {
		t.Errorf("expected protocol trojan, got %s", nodes[0].Protocol)
	}
}
