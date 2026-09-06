package mobilehost

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// DaemonEngineState represents core engine lifecycle status
type DaemonEngineState int

const (
	EngineStateStopped DaemonEngineState = iota
	EngineStateStarting
	EngineStateRunning
	EngineStateDegraded
	EngineStateCrashed
)

// EngineProcessMetrics stores engine telemetry
type EngineProcessMetrics struct {
	PID          uint32
	Uptime       time.Duration
	MemoryRSS    uint64
	RestartCount uint32
}

// SupervisorPolicy governs engine process limits
type SupervisorPolicy struct {
	MaxRestarts      uint32
	RestartCooldown  time.Duration
	MemoryLimitBytes uint64
}

// CoreEngineSupervisor manages background proxy daemon process lifecycle
type CoreEngineSupervisor struct {
	mu      sync.RWMutex
	Policy  SupervisorPolicy
	State   DaemonEngineState
	Metrics EngineProcessMetrics
}

// NewCoreEngineSupervisor creates an engine supervisor
func NewCoreEngineSupervisor(policy SupervisorPolicy) *CoreEngineSupervisor {
	return &CoreEngineSupervisor{
		Policy: policy,
		State:  EngineStateStopped,
	}
}

// Start transitions engine to Running with given PID
func (s *CoreEngineSupervisor) Start(pid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.State == EngineStateRunning {
		return errors.New("engine is already running")
	}

	s.State = EngineStateRunning
	s.Metrics.PID = pid
	s.Metrics.Uptime = 0
	return nil
}

// Stop cleanly shuts down the engine
func (s *CoreEngineSupervisor) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.State = EngineStateStopped
	s.Metrics.PID = 0
	return nil
}

// HandleProcessExit processes unexpected crashes
func (s *CoreEngineSupervisor) HandleProcessExit(exitCode int) DaemonEngineState {
	s.mu.Lock()
	defer s.mu.Unlock()

	if exitCode == 0 {
		s.State = EngineStateStopped
		s.Metrics.PID = 0
		return s.State
	}

	s.Metrics.RestartCount++
	if s.Metrics.RestartCount > s.Policy.MaxRestarts {
		s.State = EngineStateCrashed
	} else {
		s.State = EngineStateDegraded
	}
	return s.State
}

// RecordHeartbeat checks memory limits and updates uptime
func (s *CoreEngineSupervisor) RecordHeartbeat(delta time.Duration, rssBytes uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.State != EngineStateRunning && s.State != EngineStateDegraded {
		return errors.New("engine inactive")
	}

	s.Metrics.Uptime += delta
	s.Metrics.MemoryRSS = rssBytes

	if rssBytes > s.Policy.MemoryLimitBytes {
		s.State = EngineStateDegraded
		return fmt.Errorf("memory limit exceeded: %d > %d", rssBytes, s.Policy.MemoryLimitBytes)
	}

	return nil
}
