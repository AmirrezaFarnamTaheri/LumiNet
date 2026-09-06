package routing

import (
	"testing"
)

func TestPacDiffSynchronizer(t *testing.T) {
	initial := []string{"google.com", "twitter.com"}
	sync := NewPacDiffSynchronizer(initial)

	upstream := []string{"google.com", "youtube.com"}
	delta := sync.ComputeDelta(upstream)

	if len(delta.AddedDomains) != 1 || delta.AddedDomains[0] != "youtube.com" {
		t.Fatalf("expected youtube.com added, got %v", delta.AddedDomains)
	}
	if len(delta.RemovedDomains) != 1 || delta.RemovedDomains[0] != "twitter.com" {
		t.Fatalf("expected twitter.com removed, got %v", delta.RemovedDomains)
	}

	count, err := sync.ApplyDelta(delta)
	if err != nil {
		t.Fatalf("apply delta failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 rules, got %d", count)
	}
	if !sync.ContainsRule("youtube.com") || sync.ContainsRule("twitter.com") {
		t.Fatalf("ruleset mismatch after apply")
	}
}
