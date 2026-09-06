package transport

import (
	"testing"
	"time"
)

func TestAutonomousEvasionOrchestratorEscalation(t *testing.T) {
	orch := NewAutonomousEvasionOrchestrator(2, 5*time.Millisecond)

	mode, shifted := orch.RecordTcpReset()
	if shifted || mode != EvasionStandard {
		t.Errorf("should not shift on 1st RST")
	}

	mode, shifted = orch.RecordTcpReset()
	if !shifted || mode != EvasionSplit {
		t.Errorf("expected shift to SPLIT on 2nd RST, got %s", mode)
	}

	time.Sleep(10 * time.Millisecond)
	orch.RecordTcpReset()
	mode, shifted = orch.RecordTcpReset()
	if !shifted || mode != EvasionFakeTtl {
		t.Errorf("expected shift to FAKE_TTL, got %s", mode)
	}
}
