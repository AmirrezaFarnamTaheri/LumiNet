package proxyconfig

import (
	"testing"
)

func TestNodePoolAggregator(t *testing.T) {
	agg := NewNodePoolAggregator()
	lines := []string{
		"ss://aes-256-gcm:pass@node1.example.org:8388",
		"trojan://secret@node2.example.org:443#Tokyo",
		"invalid-line",
	}

	count := agg.IngestRawEntries(lines, 1700000000)
	if count != 2 {
		t.Fatalf("expected 2 ingested nodes, got %d", count)
	}

	agg.UpdateHealth("trojan:node2.example.org:443", 35, true)
	agg.UpdateHealth("ss:node1.example.org:8388", 350, true)

	ranked := agg.RankNodes(40.0)
	if len(ranked) != 2 {
		t.Fatalf("expected 2 ranked nodes, got %d", len(ranked))
	}

	if ranked[0].Host != "node2.example.org" {
		t.Errorf("expected node2.example.org to rank first, got %s", ranked[0].Host)
	}
}
