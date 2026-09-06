package proxy

import (
	"net"
	"testing"
)

func TestIPTrie(t *testing.T) {
	trie := NewIPTrie()

	// Parse test CIDRs
	_, net1, _ := net.ParseCIDR("192.168.1.0/24")
	_, net2, _ := net.ParseCIDR("10.0.0.0/8")
	_, net3, _ := net.ParseCIDR("2001:db8::/32")

	trie.Insert(net1)
	trie.Insert(net2)
	trie.Insert(net3)

	// Test matches
	if !trie.Contains(net.ParseIP("192.168.1.15")) {
		t.Error("expected 192.168.1.15 to match 192.168.1.0/24")
	}
	if !trie.Contains(net.ParseIP("10.250.0.1")) {
		t.Error("expected 10.250.0.1 to match 10.0.0.0/8")
	}
	if !trie.Contains(net.ParseIP("2001:db8:a::1")) {
		t.Error("expected 2001:db8:a::1 to match 2001:db8::/32")
	}

	// Test mismatches
	if trie.Contains(net.ParseIP("192.168.2.1")) {
		t.Error("unexpected match for 192.168.2.1")
	}
	if trie.Contains(net.ParseIP("8.8.8.8")) {
		t.Error("unexpected match for 8.8.8.8")
	}
	if trie.Contains(net.ParseIP("2001:db9::1")) {
		t.Error("unexpected match for 2001:db9::1")
	}
}
