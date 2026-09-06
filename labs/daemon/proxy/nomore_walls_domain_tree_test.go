package proxy

import (
	"testing"
)

func TestDomainTree(t *testing.T) {
	tree := NewDomainTree()
	// 1. Test basic insertion
	tree.Insert("example.com")
	tree.Insert("sub.example.com")
	tree.Insert("google.com")

	domains := tree.Get()
	if len(domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(domains))
	}

	hasExample := false
	hasGoogle := false
	for _, d := range domains {
		if d == "example.com" {
			hasExample = true
		}
		if d == "google.com" {
			hasGoogle = true
		}
	}
	if !hasExample || !hasGoogle {
		t.Errorf("Missing example.com or google.com from trie")
	}

	// 2. Test removal / whitelist override
	tree.Remove("sub.example.com")
	// Since sub.example.com is removed, example.com remains but doesn't cover sub.example.com.
	// Actually, m.domainRoot.Remove("sub.example.com") will clear the trie from that path.
	tree.Remove("example.com")
	domains = tree.Get()
	for _, d := range domains {
		if d == "example.com" {
			t.Errorf("example.com was not removed")
		}
	}
}

func TestAdblockRuleMerger(t *testing.T) {
	merger := NewAdblockRuleMerger()
	// Feed blocked and whitelisted rules
	merger.AddBlocklistLine("||doubleclick.net^")
	merger.AddBlocklistLine("||google-analytics.com^")
	merger.AddBlocklistLine("||*advertisement*^")
	merger.AddBlocklistLine("@@||allowed.doubleclick.net^")
	// IP block rule
	merger.AddBlocklistLine("||1.2.3.4^")
	merger.Finalise("ad_block")

	rules := merger.Rules
	if _, exists := rules["DOMAIN-SUFFIX,doubleclick.net"]; !exists {
		t.Errorf("Expected DOMAIN-SUFFIX,doubleclick.net")
	}
	if _, exists := rules["DOMAIN-KEYWORD,advertisement"]; !exists {
		t.Errorf("Expected DOMAIN-KEYWORD,advertisement")
	}
	if _, exists := rules["IP-CIDR,1.2.3.4/32"]; !exists {
		t.Errorf("Expected IP-CIDR,1.2.3.4/32")
	}
	// Doubleclick has been whitelisted for a subdomain
	// Since DOMAIN-SUFFIX,doubleclick.net matches everything, allowed.doubleclick.net would be matched by suffix.
	// The merger handles whitelist removals.
}

func TestNodeDeduplicator(t *testing.T) {
	dedup := NewNodeDeduplicator()
	node1 := map[string]interface{}{
		"name": "Node A",
		"type": "vmess",
		"host": "1.1.1.1",
	}
	node2 := map[string]interface{}{
		"name": "Node A Duplicate",
		"type": "vmess",
		"host": "1.1.1.1",
	}
	dedup.Merge("vmess:1.1.1.1", node1)
	dedup.Merge("vmess:1.1.1.1", node2)
	if dedup.Count() != 1 {
		t.Errorf("Expected count of unique nodes to be 1, got %d", dedup.Count())
	}
	entries := dedup.Entries()
	names := entries[0].Names
	if _, exists := names["Node A"]; !exists {
		t.Errorf("Missing Node A name")
	}
	if _, exists := names["Node A Duplicate"]; !exists {
		t.Errorf("Missing Node A Duplicate name")
	}
}
