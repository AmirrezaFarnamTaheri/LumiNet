package proxyconfig

import (
	"encoding/base64"
	"testing"
)

func TestCommunityFeedParser(t *testing.T) {
	parser := NewCommunityFeedParser()

	vlessURI := "vless://uuid-1234@node1.example.com:443?type=ws&sni=cdn.example.com#US-East"
	node, err := parser.ParseURI(vlessURI)
	if err != nil {
		t.Fatalf("failed to parse vless uri: %v", err)
	}
	if node.Protocol != "vless" || node.Server != "node1.example.com" || node.Port != 443 || node.SNI != "cdn.example.com" {
		t.Fatalf("unexpected node parsed: %+v", node)
	}

	trojanURI := "trojan://secret@node2.example.com:8443?sni=node2.example.com#DE-Frankfurt"
	nodeTrojan, err := parser.ParseURI(trojanURI)
	if err != nil || nodeTrojan.Protocol != "trojan" {
		t.Fatalf("failed to parse trojan uri: %v", err)
	}

	// Test feed decode & deduplicate
	plainFeed := "vless://u1@1.2.3.4:443\nvless://u1@1.2.3.4:443\ntrojan://p1@1.2.3.4:8443"
	b64Feed := base64.StdEncoding.EncodeToString([]byte(plainFeed))

	count := parser.ParseFeedContent(b64Feed)
	if count != 3 {
		t.Fatalf("expected 3 parsed nodes, got %d", count)
	}

	deduped := parser.Deduplicate()
	if deduped != 1 || len(parser.Nodes) != 2 {
		t.Fatalf("expected 1 removed, remaining 2, got %d removed, %d remaining", deduped, len(parser.Nodes))
	}
}
