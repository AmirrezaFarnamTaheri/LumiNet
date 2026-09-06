package proxyconfig

import (
	"testing"
)

func TestSubscriptionNodeExtractor(t *testing.T) {
	extractor := &SubscriptionNodeExtractor{}

	ssURI := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@192.168.1.1:8388#MyServer"
	node, ok := extractor.ParseNodeURI(ssURI)
	if !ok {
		t.Fatalf("failed to parse SS URI")
	}
	if node.NodeType != NodeShadowsocks || node.Address != "192.168.1.1" || node.Port != 8388 || node.Remark != "MyServer" {
		t.Fatalf("unexpected SS node: %+v", node)
	}

	trojanURI := "trojan://secret-pwd@edge.example.com:443#Primary-Trojan"
	tnode, tok := extractor.ParseNodeURI(trojanURI)
	if !tok {
		t.Fatalf("failed to parse Trojan URI")
	}
	if tnode.NodeType != NodeTrojan || tnode.Address != "edge.example.com" || tnode.Port != 443 || tnode.Credential != "secret-pwd" {
		t.Fatalf("unexpected Trojan node: %+v", tnode)
	}
}
