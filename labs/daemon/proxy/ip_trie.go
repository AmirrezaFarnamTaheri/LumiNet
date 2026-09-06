package proxy

import (
	"net"
)

// IPTrieNode represents a node in the binary trie.
type IPTrieNode struct {
	children [2]*IPTrieNode
	isEnd    bool
}

// IPTrie stores CIDR blocks for fast IP lookup.
type IPTrie struct {
	root *IPTrieNode
}

// NewIPTrie creates an empty IPTrie.
func NewIPTrie() *IPTrie {
	return &IPTrie{root: &IPTrieNode{}}
}

// Insert adds a CIDR block to the trie.
func (t *IPTrie) Insert(ipNet *net.IPNet) {
	if ipNet == nil {
		return
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		ip = ipNet.IP.To16()
	}
	if ip == nil {
		return
	}

	ones, _ := ipNet.Mask.Size()

	curr := t.root
	for i := 0; i < ones; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (ip[byteIdx] >> bitIdx) & 1

		if curr.children[bit] == nil {
			curr.children[bit] = &IPTrieNode{}
		}
		curr = curr.children[bit]
		if curr.isEnd {
			// Subsumed by a shorter prefix, no need to go deeper
			return
		}
	}
	curr.isEnd = true
}

// Contains checks if the IP is covered by any CIDR in the trie.
func (t *IPTrie) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	bits := 32
	ipBytes := ip4
	if ip4 == nil {
		ipBytes = ip.To16()
		bits = 128
	}
	if ipBytes == nil {
		return false
	}

	curr := t.root
	for i := 0; i < bits; i++ {
		if curr.isEnd {
			return true
		}
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (ipBytes[byteIdx] >> bitIdx) & 1

		if curr.children[bit] == nil {
			return false
		}
		curr = curr.children[bit]
	}
	return curr.isEnd
}
