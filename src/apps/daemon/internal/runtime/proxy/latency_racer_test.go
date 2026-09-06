package proxy

import (
	"testing"
)

func TestLatencyRaceSelector(t *testing.T) {
	racer := NewLatencyRaceSelector()
	racer.RegisterNode("n1", "vless", "1.1.1.1:443")
	racer.RegisterNode("n2", "ss", "2.2.2.2:443")

	racer.RecordProbe("n1", 120.0)
	racer.RecordProbe("n2", 45.0)

	best, err := racer.SelectFastest()
	if err != nil {
		t.Fatalf("SelectFastest failed: %v", err)
	}
	if best.NodeID != "n2" || best.EwmaLatencyMs != 45.0 {
		t.Fatalf("expected n2, got %s", best.NodeID)
	}
}
