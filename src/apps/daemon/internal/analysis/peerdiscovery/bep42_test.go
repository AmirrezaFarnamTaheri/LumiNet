package peerdiscovery

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func TestGenerateIPv4NodeIDMatchesPublishedBEP42Prefixes(t *testing.T) {
	cases := []struct {
		ip     string
		random byte
		prefix string
	}{
		{ip: "124.31.75.21", random: 1, prefix: "5fbfb"},
		{ip: "21.75.31.124", random: 86, prefix: "5a3ce"},
		{ip: "65.23.51.170", random: 22, prefix: "a5d43"},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			id, err := GenerateIPv4NodeID(netip.MustParseAddr(tc.ip), tc.random, bytes.NewReader(make([]byte, 17)))
			if err != nil {
				t.Fatal(err)
			}
			if got := id.String()[:5]; got != tc.prefix {
				t.Fatalf("prefix=%s, want %s (id=%s)", got, tc.prefix, id)
			}
			if !ValidIPv4NodeID(id, netip.MustParseAddr(tc.ip)) {
				t.Fatal("generated node ID did not validate")
			}
		})
	}
}

func TestBEP42RejectsChangedIPAndMalformedID(t *testing.T) {
	id, err := GenerateIPv4NodeID(netip.MustParseAddr("8.8.8.8"), 9, bytes.NewReader([]byte(strings.Repeat("x", 17))))
	if err != nil {
		t.Fatal(err)
	}
	if ValidIPv4NodeID(id, netip.MustParseAddr("8.8.4.4")) {
		t.Fatal("node ID validated against a different IP")
	}
	if _, err := ParseNodeID("abcd"); err == nil {
		t.Fatal("expected short node ID rejection")
	}
	if _, err := ParseNodeID(strings.Repeat("z", 40)); err == nil {
		t.Fatal("expected non-hex node ID rejection")
	}
}
