package proxyconfig

import (
	"strings"
	"testing"
)

func TestPacSubscriptionOrchestrator(t *testing.T) {
	initial := []string{"youtube.com", "netflix.com"}
	orch := NewPacSubscriptionOrchestrator(initial, 10808)

	orch.RegisterSubscriptionSource("https://free-nodes.org/sub", 3600)
	rawNodes := "trojan://secret@fast.node:443#Fast\nss://method:pass@slow.node:8388"
	crawled := orch.ExecuteCrawlAndIngest("https://free-nodes.org/sub", rawNodes, 1000)
	if crawled != 2 {
		t.Fatalf("expected 2 crawled nodes, got %d", crawled)
	}

	for i := 0; i < 5; i++ {
		orch.RecordNodeProbe("trojan:fast.node:443", 30, true)
		orch.RecordNodeProbe("ss:slow.node:8388", 450, true)
	}

	summary := orch.GetSummary()
	if summary.TotalCrawled != 2 || summary.TotalActivePool != 2 || summary.UsableTierACount != 1 {
		t.Fatalf("summary unexpected: %+v", summary)
	}

	upstream := []string{"youtube.com", "netflix.com", "wikipedia.org"}
	delta, err := orch.UpdatePacWithUpstream(upstream)
	if err != nil {
		t.Fatalf("update pac upstream failed: %v", err)
	}
	if len(delta.AddedDomains) != 1 || delta.AddedDomains[0] != "wikipedia.org" {
		t.Fatalf("delta added mismatch: %v", delta.AddedDomains)
	}

	script := orch.ExportActivePacScript()
	if !strings.Contains(script, "wikipedia.org") || !strings.Contains(script, "127.0.0.1:10808") {
		t.Fatalf("exported PAC script missing updated domain")
	}
}
