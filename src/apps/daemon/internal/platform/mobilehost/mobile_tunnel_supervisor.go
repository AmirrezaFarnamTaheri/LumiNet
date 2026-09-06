package mobilehost

import (
	"errors"
	"sync"
)

type MobileTunnelState string

const (
	TunnelStopped      MobileTunnelState = "stopped"
	TunnelStarting     MobileTunnelState = "starting"
	TunnelRunning      MobileTunnelState = "running"
	TunnelPausing      MobileTunnelState = "pausing"
	TunnelReconnecting MobileTunnelState = "reconnecting"
	TunnelFailed       MobileTunnelState = "failed"
)

type MobileTunnelConfig struct {
	TunName          string
	Mtu              uint16
	IPv4Address      string
	IPv4Netmask      string
	DNSServers       []string
	IncludedPackages map[string]struct{}
	ExcludedPackages map[string]struct{}
}

type MobileTunnelSupervisor struct {
	mu               sync.RWMutex
	config           MobileTunnelConfig
	state            MobileTunnelState
	activeTunFd      int
	totalReconnects  uint32
}

func NewMobileTunnelSupervisor(config MobileTunnelConfig) *MobileTunnelSupervisor {
	if config.IncludedPackages == nil {
		config.IncludedPackages = make(map[string]struct{})
	}
	if config.ExcludedPackages == nil {
		config.ExcludedPackages = make(map[string]struct{})
	}
	return &MobileTunnelSupervisor{
		config:          config,
		state:           TunnelStopped,
		activeTunFd:     -1,
		totalReconnects: 0,
	}
}

func (s *MobileTunnelSupervisor) Start(tunFd int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == TunnelRunning {
		return errors.New("tunnel already running")
	}
	s.activeTunFd = tunFd
	s.state = TunnelRunning
	return nil
}

func (s *MobileTunnelSupervisor) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = TunnelStopped
	s.activeTunFd = -1
}

func (s *MobileTunnelSupervisor) TriggerReconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalReconnects++
	s.state = TunnelReconnecting
}

func (s *MobileTunnelSupervisor) IsPackageRouted(pkg string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 1. Excluded takes precedence
	if _, ok := s.config.ExcludedPackages[pkg]; ok {
		return false
	}
	// 2. If inclusion set is not empty, must be in inclusion set
	if len(s.config.IncludedPackages) > 0 {
		_, ok := s.config.IncludedPackages[pkg]
		return ok
	}
	// 3. Otherwise route all
	return true
}

func (s *MobileTunnelSupervisor) State() MobileTunnelState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *MobileTunnelSupervisor) TunFd() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeTunFd
}

func (s *MobileTunnelSupervisor) ReconnectCount() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.totalReconnects
}
