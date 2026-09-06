package diagnostics

import (
	"testing"
)

func TestAdaptiveMtuDiscovery(t *testing.T) {
	disc := NewAdaptiveMtuDiscovery(1280, 1500)
	for i := 0; i < 15; i++ {
		probe := disc.NextProbeSize()
		ok := probe <= 1420
		disc.RecordResult(probe, ok)
		if disc.ConvergedMtu != nil {
			break
		}
	}
	if disc.OptimalMtu() != 1420 {
		t.Fatalf("expected 1420, got %d", disc.OptimalMtu())
	}
	if disc.WireguardPayloadMtu(false) != 1360 {
		t.Fatalf("expected 1360, got %d", disc.WireguardPayloadMtu(false))
	}
}
