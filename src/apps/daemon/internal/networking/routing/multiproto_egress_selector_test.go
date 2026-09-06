package routing

import (
	"testing"
)

func TestMultiprotoEgressSelector(t *testing.T) {
	selector := NewMultiprotoEgressSelector()

	t1 := EgressTarget{
		TargetID:    "target-wg",
		Protocol:    EgressWireGuard,
		Weight:      10,
		LatencyMs:   100,
		LossPercent: 2.0,
		IsActive:    true,
	}

	t2 := EgressTarget{
		TargetID:    "target-vless",
		Protocol:    EgressVless,
		Weight:      10,
		LatencyMs:   30,
		LossPercent: 0.0,
		IsActive:    true,
	}

	selector.AddTarget(t1)
	selector.AddTarget(t2)

	// t2 has much lower latency (30ms vs 100ms)
	best, err := selector.SelectBestEgress("")
	if err != nil {
		t.Fatalf("failed to select best: %v", err)
	}
	if best.TargetID != "target-vless" {
		t.Fatalf("expected target-vless, got %s", best.TargetID)
	}

	// But if WireGuard is explicitly preferred with +50 bonus:
	// t1 score: 100 - 100 - 40 + 50 = 10
	// t2 score: 100 - 30 - 0 = 70 (t2 still wins because latency difference is 70)
	// Now if t2 experiences high loss:
	selector.UpdateMetrics("target-vless", 80, 5.0, true)
	// t2 score: 100 - 80 - 100 = -80
	bestAfter, _ := selector.SelectBestEgress(EgressWireGuard)
	if bestAfter.TargetID != "target-wg" {
		t.Fatalf("expected target-wg to win after degradation, got %s", bestAfter.TargetID)
	}
}
