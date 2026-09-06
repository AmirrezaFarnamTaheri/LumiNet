package safety

import (
	"testing"
	"time"
)

func TestTunnelProcessSupervisorBackoff(t *testing.T) {
	cfg := ProcessSupervisorConfig{
		MaxRestarts: 3,
		BaseBackoff: 10 * time.Millisecond,
		MaxBackoff:  50 * time.Millisecond,
	}

	sup := NewTunnelProcessSupervisor(cfg)

	delay1, ok1 := sup.RecordCrash()
	if !ok1 || delay1 != 10*time.Millisecond {
		t.Errorf("expected 10ms backoff on first crash, got %v", delay1)
	}

	delay2, ok2 := sup.RecordCrash()
	if !ok2 || delay2 != 20*time.Millisecond {
		t.Errorf("expected 20ms backoff on second crash, got %v", delay2)
	}

	delay3, ok3 := sup.RecordCrash()
	if !ok3 || delay3 != 40*time.Millisecond {
		t.Errorf("expected 40ms backoff on third crash, got %v", delay3)
	}

	_, ok4 := sup.RecordCrash()
	if ok4 {
		t.Errorf("expected max restarts to be exceeded")
	}
}
