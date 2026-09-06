package dns

import (
	"testing"
)

func TestSNIRoutingTable(t *testing.T) {
	table := NewSNIRoutingTable()
	table.AddExactRoute("edge.custom.org", "10.10.10.1")
	table.AddWildcardRoute("*.youtube.com", "192.0.2.100")
	table.AddSubstringRoute("instagram", "198.51.100.50")

	if table.Count() != 3 {
		t.Fatalf("expected 3 routes, got %d", table.Count())
	}

	// Exact match
	ip, ok := table.ResolveRoute("edge.custom.org.")
	if !ok || ip != "10.10.10.1" {
		t.Fatalf("expected exact match 10.10.10.1, got ip=%s ok=%v", ip, ok)
	}

	// Wildcard match
	ip, ok = table.ResolveRoute("video.i.youtube.com")
	if !ok || ip != "192.0.2.100" {
		t.Fatalf("expected wildcard match 192.0.2.100, got ip=%s ok=%v", ip, ok)
	}

	// Base wildcard match
	ip, ok = table.ResolveRoute("youtube.com")
	if !ok || ip != "192.0.2.100" {
		t.Fatalf("expected base domain match 192.0.2.100, got ip=%s ok=%v", ip, ok)
	}

	// Substring match
	ip, ok = table.ResolveRoute("static.cdninstagram.com")
	if !ok || ip != "198.51.100.50" {
		t.Fatalf("expected substring match 198.51.100.50, got ip=%s ok=%v", ip, ok)
	}

	// No match
	_, ok = table.ResolveRoute("unrelated.example.com")
	if ok {
		t.Fatalf("expected no match for unrelated domain")
	}
}
