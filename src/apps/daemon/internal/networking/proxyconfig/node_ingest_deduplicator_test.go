package proxyconfig

import (
	"testing"
)

func TestNodeIngestDeduplicator(t *testing.T) {
	dedup := NewNodeIngestDeduplicator()

	n1 := ScrapedNode{
		Host:     "node1.net",
		Port:     443,
		Protocol: "trojan",
		Source:   "feed_a",
		PingMs:   150,
		IsAlive:  true,
	}

	n2 := ScrapedNode{
		Host:     "NODE1.NET", // duplicate case-insensitive
		Port:     443,
		Protocol: "trojan",
		Source:   "feed_b",
		PingMs:   180,
		IsAlive:  true,
	}

	n3 := ScrapedNode{
		Host:     "node2.net",
		Port:     8443,
		Protocol: "vmess",
		Source:   "feed_a",
		PingMs:   60,
		IsAlive:  true,
	}

	if !dedup.IngestNode(n1) {
		t.Fatal("expected n1 to be ingested")
	}
	if dedup.IngestNode(n2) {
		t.Fatal("expected n2 to be rejected as duplicate")
	}
	if !dedup.IngestNode(n3) {
		t.Fatal("expected n3 to be ingested")
	}

	if dedup.TotalUnique() != 2 {
		t.Fatalf("expected 2 unique nodes, got %d", dedup.TotalUnique())
	}
	if dedup.CountForSource("feed_a") != 2 {
		t.Fatalf("expected 2 for feed_a, got %d", dedup.CountForSource("feed_a"))
	}
	if dedup.CountForSource("feed_b") != 0 {
		t.Fatalf("expected 0 for feed_b, got %d", dedup.CountForSource("feed_b"))
	}

	ranked := dedup.GetRankedNodes()
	if len(ranked) != 2 {
		t.Fatalf("expected 2 ranked nodes, got %d", len(ranked))
	}
	if ranked[0].Host != "node2.net" {
		t.Fatalf("expected node2.net first due to lower ping, got %s", ranked[0].Host)
	}
}
