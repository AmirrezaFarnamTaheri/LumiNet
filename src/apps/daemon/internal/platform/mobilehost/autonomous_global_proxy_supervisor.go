package mobilehost

import (
	"sync"
	"time"
)

// SubsystemHealthRecord tracks state of an individual absorbed subsystem
type SubsystemHealthRecord struct {
	Name              string
	Plane             string
	IsHealthy         bool
	ActiveConnections uint32
	LastHeartbeat     time.Time
	LastError         string
}

// GlobalSupervisionReport summarizes total cluster status
type GlobalSupervisionReport struct {
	TotalSubsystems          int
	HealthySubsystems        int
	HealthPercentage         float32
	TotalActiveConnections   uint32
	KillswitchEngaged        bool
}

// AutonomousGlobalProxySupervisor supervises all 147 Wave 2 absorbed modules
type AutonomousGlobalProxySupervisor struct {
	mu                     sync.RWMutex
	Subsystems             map[string]*SubsystemHealthRecord
	KillswitchEngaged      bool
	AutoRemediationEnabled bool
}

// NewAutonomousGlobalProxySupervisor creates a global proxy supervisor
func NewAutonomousGlobalProxySupervisor(autoRemediation bool) *AutonomousGlobalProxySupervisor {
	return &AutonomousGlobalProxySupervisor{
		Subsystems:             make(map[string]*SubsystemHealthRecord),
		AutoRemediationEnabled: autoRemediation,
	}
}

// RegisterSubsystem adds a module to supervision
func (s *AutonomousGlobalProxySupervisor) RegisterSubsystem(name, plane string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Subsystems[name] = &SubsystemHealthRecord{
		Name:          name,
		Plane:         plane,
		IsHealthy:     true,
		LastHeartbeat: time.Now(),
	}
}

// UpdateHealth updates health status and connection metrics
func (s *AutonomousGlobalProxySupervisor) UpdateHealth(name string, healthy bool, conns uint32, errStr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	sub, ok := s.Subsystems[name]
	if !ok {
		return false
	}

	sub.IsHealthy = healthy
	sub.ActiveConnections = conns
	sub.LastHeartbeat = time.Now()
	sub.LastError = errStr
	return true
}

// SetKillswitch engages or disengages global emergency killswitch
func (s *AutonomousGlobalProxySupervisor) SetKillswitch(engaged bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.KillswitchEngaged = engaged
	if engaged {
		for _, sub := range s.Subsystems {
			sub.ActiveConnections = 0
		}
	}
}

// GenerateReport produces aggregate system telemetry
func (s *AutonomousGlobalProxySupervisor) GenerateReport() GlobalSupervisionReport {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.Subsystems)
	healthy := 0
	var totalConns uint32

	for _, sub := range s.Subsystems {
		if sub.IsHealthy {
			healthy++
		}
		totalConns += sub.ActiveConnections
	}

	pct := float32(100.0)
	if total > 0 {
		pct = (float32(healthy) / float32(total)) * 100.0
	}

	return GlobalSupervisionReport{
		TotalSubsystems:        total,
		HealthySubsystems:      healthy,
		HealthPercentage:       pct,
		TotalActiveConnections: totalConns,
		KillswitchEngaged:      s.KillswitchEngaged,
	}
}

// IdentifyRemediationTargets finds unhealthy or stale subsystems
func (s *AutonomousGlobalProxySupervisor) IdentifyRemediationTargets(now time.Time, staleTimeout time.Duration) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.AutoRemediationEnabled {
		return nil
	}

	var targets []string
	for name, sub := range s.Subsystems {
		if !sub.IsHealthy || now.Sub(sub.LastHeartbeat) > staleTimeout {
			targets = append(targets, name)
		}
	}
	return targets
}
