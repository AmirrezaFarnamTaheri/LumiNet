package mobilehost

import (
	"testing"
	"time"
)

func TestCoreEngineSupervisor(t *testing.T) {
	policy := SupervisorPolicy{
		MaxRestarts:      2,
		RestartCooldown:  1 * time.Second,
		MemoryLimitBytes: 100 * 1024 * 1024, // 100 MB
	}
	s := NewCoreEngineSupervisor(policy)

	if s.State != EngineStateStopped {
		t.Fatalf("expected initial state stopped")
	}

	if err := s.Start(9999); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	if s.State != EngineStateRunning || s.Metrics.PID != 9999 {
		t.Fatalf("expected running state with PID 9999")
	}

	// Normal heartbeat
	if err := s.RecordHeartbeat(10*time.Second, 50*1024*1024); err != nil {
		t.Fatalf("unexpected heartbeat error: %v", err)
	}

	// High memory heartbeat
	err := s.RecordHeartbeat(5*time.Second, 150*1024*1024)
	if err == nil || s.State != EngineStateDegraded {
		t.Fatalf("expected degraded state on memory limit exceed")
	}

	// Crash handling
	s.HandleProcessExit(1) // Crash 1
	if s.State != EngineStateDegraded || s.Metrics.RestartCount != 1 {
		t.Fatalf("expected degraded on first crash")
	}

	s.HandleProcessExit(1) // Crash 2
	if s.State != EngineStateDegraded || s.Metrics.RestartCount != 2 {
		t.Fatalf("expected degraded on second crash")
	}

	s.HandleProcessExit(1) // Crash 3 -> Crashed
	if s.State != EngineStateCrashed {
		t.Fatalf("expected crashed state after exceeding max restarts")
	}
}
