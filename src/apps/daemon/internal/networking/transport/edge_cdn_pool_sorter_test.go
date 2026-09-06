package transport

import (
	"testing"
)

func TestEdgeCdnPoolSorter(t *testing.T) {
	sorter := NewEdgeCdnPoolSorter(300)
	sorter.AddIP("142.250.190.46")
	sorter.AddIP("172.217.16.206")
	sorter.AddIP("216.58.214.206")

	sorter.UpdateProbeResult("142.250.190.46", 120, true)
	sorter.UpdateProbeResult("172.217.16.206", 45, true)
	sorter.UpdateProbeResult("216.58.214.206", 450, true) // exceeds 300 threshold

	best, ok := sorter.BestIP()
	if !ok || best != "172.217.16.206" {
		t.Fatalf("expected best IP 172.217.16.206, got %s", best)
	}

	sorted := sorter.GetSortedFastest()
	if len(sorted) != 2 {
		t.Fatalf("expected 2 available IPs, got %d", len(sorted))
	}
	if sorted[0].LatencyMs != 45 {
		t.Fatalf("expected 45ms, got %d", sorted[0].LatencyMs)
	}
	if sorted[1].LatencyMs != 120 {
		t.Fatalf("expected 120ms, got %d", sorted[1].LatencyMs)
	}
}
