package diagnostics

import (
	"strings"
	"testing"
)

func TestEdgeWorkerSelector(t *testing.T) {
	sel := NewEdgeWorkerSelector()
	sel.AddOrUpdate("w1.dev", "104.16.1.1", 443, 100, 0.0)
	sel.AddOrUpdate("w2.dev", "104.16.2.2", 443, 80, 2.0)
	sel.AddOrUpdate("w3.dev", "104.16.3.3", 443, 85, 0.0)

	best := sel.SelectBest()
	if best == nil || best.CleanIP != "104.16.3.3" {
		t.Fatalf("expected 104.16.3.3 as best, got %+v", best)
	}

	uri := sel.SynthesizeVlessURI(best, "test-uuid", "w3.dev")
	if !strings.Contains(uri, "104.16.3.3:443") {
		t.Fatalf("invalid uri: %s", uri)
	}
}
