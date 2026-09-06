package safety

import (
	"sync"
	"time"
)

// SupervisorProcessState represents current state of a child tunnel process.
type SupervisorProcessState string

const (
	StateStopped  SupervisorProcessState = "STOPPED"
	StateStarting SupervisorProcessState = "STARTING"
	StateRunning  SupervisorProcessState = "RUNNING"
	StateCrashed  SupervisorProcessState = "CRASHED"
)

// ProcessSupervisorConfig holds configuration for process resilience.
type ProcessSupervisorConfig struct {
	MaxRestarts   int           `json:"max_restarts"`
	BaseBackoff   time.Duration `json:"base_backoff"`
	MaxBackoff    time.Duration `json:"max_backoff"`
	ResetInterval time.Duration `json:"reset_interval"`
}

// TunnelProcessSupervisor manages child binary lifecycles with exponential backoff.
type TunnelProcessSupervisor struct {
	mu             sync.Mutex
	cfg            ProcessSupervisorConfig
	state          SupervisorProcessState
	restartCount   int
	lastRestart    time.Time
	currentBackoff time.Duration
}

// NewTunnelProcessSupervisor constructs a supervisor.
func NewTunnelProcessSupervisor(cfg ProcessSupervisorConfig) *TunnelProcessSupervisor {
	if cfg.MaxRestarts <= 0 {
		cfg.MaxRestarts = 5
	}
	if cfg.BaseBackoff == 0 {
		cfg.BaseBackoff = 1 * time.Second
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 30 * time.Second
	}
	if cfg.ResetInterval == 0 {
		cfg.ResetInterval = 5 * time.Minute
	}

	return &TunnelProcessSupervisor{
		cfg:            cfg,
		state:          StateStopped,
		currentBackoff: cfg.BaseBackoff,
	}
}

// RecordCrash increments restart counter and calculates required backoff.
func (s *TunnelProcessSupervisor) RecordCrash() (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if !s.lastRestart.IsZero() && now.Sub(s.lastRestart) > s.cfg.ResetInterval {
		s.restartCount = 0
		s.currentBackoff = s.cfg.BaseBackoff
	}

	s.restartCount++
	s.lastRestart = now
	s.state = StateCrashed

	if s.restartCount > s.cfg.MaxRestarts {
		return 0, false // Cannot restart, limit exceeded
	}

	delay := s.currentBackoff
	s.currentBackoff *= 2
	if s.currentBackoff > s.cfg.MaxBackoff {
		s.currentBackoff = s.cfg.MaxBackoff
	}

	return delay, true
}

// SetState transitions the current state safely.
func (s *TunnelProcessSupervisor) SetState(state SupervisorProcessState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
	if state == StateRunning {
		// Reset backoff if stable
		s.currentBackoff = s.cfg.BaseBackoff
	}
}

// State returns the current status.
func (s *TunnelProcessSupervisor) State() SupervisorProcessState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}
