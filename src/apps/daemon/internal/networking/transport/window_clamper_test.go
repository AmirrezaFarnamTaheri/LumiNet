package transport

import "testing"

func TestWindowClamper(t *testing.T) {
	clamper := NewWindowClamper(4)
	if clamper.ClampWindow(64240, true) != 4 {
		t.Errorf("expected clamped window to be 4 during handshake")
	}
	if clamper.ClampWindow(64240, false) != 64240 {
		t.Errorf("expected unclamped window when handshake finished")
	}
	if !clamper.IsRstLegitimate(105000, 100000, 10000) {
		t.Errorf("expected legitimate RST")
	}
	if clamper.IsRstLegitimate(500000, 100000, 10000) {
		t.Errorf("expected forged RST to be detected")
	}
}
