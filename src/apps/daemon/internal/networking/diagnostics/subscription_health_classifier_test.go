package diagnostics

import (
	"testing"
)

func TestSubscriptionHealthClassifier(t *testing.T) {
	cl := NewSubscriptionHealthClassifier(10)

	// Node 1: Fast & reliable
	for i := 0; i < 10; i++ {
		cl.RecordSample("node-fast", 45, true)
	}
	if cl.ClassifyNode("node-fast") != TierAExcellent {
		t.Fatalf("expected TierAExcellent for node-fast")
	}

	// Node 2: Moderate
	for i := 0; i < 10; i++ {
		cl.RecordSample("node-mid", 150, i != 0)
	}
	if cl.ClassifyNode("node-mid") != TierBGood {
		t.Fatalf("expected TierBGood for node-mid")
	}

	// Node 3: Failed
	for i := 0; i < 5; i++ {
		cl.RecordSample("node-dead", 0, false)
	}
	if cl.ClassifyNode("node-dead") != TierFDead {
		t.Fatalf("expected TierFDead for node-dead")
	}

	usable := cl.FilterUsableNodes(TierBGood)
	if len(usable) != 2 {
		t.Fatalf("expected 2 usable nodes, got %d", len(usable))
	}
}
