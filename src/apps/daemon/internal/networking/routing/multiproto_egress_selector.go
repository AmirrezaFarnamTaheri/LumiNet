package routing

import (
	"errors"
	"sync"
)

// OutboundEgressProtocol identifies egress protocol types
type OutboundEgressProtocol string

const (
	EgressWireGuard   OutboundEgressProtocol = "wireguard"
	EgressShadowsocks OutboundEgressProtocol = "shadowsocks"
	EgressVless       OutboundEgressProtocol = "vless"
	EgressTrojan      OutboundEgressProtocol = "trojan"
	EgressDirect      OutboundEgressProtocol = "direct"
)

// EgressTarget represents an upstream exit node
type EgressTarget struct {
	TargetID    string
	Protocol    OutboundEgressProtocol
	Weight      int
	LossPercent float64
	LatencyMs   int
	IsActive    bool
}

// MultiprotoEgressSelector selects optimal egress route based on weights and health
type MultiprotoEgressSelector struct {
	targets map[string]*EgressTarget
	mu      sync.RWMutex
}

// NewMultiprotoEgressSelector creates a new egress selector
func NewMultiprotoEgressSelector() *MultiprotoEgressSelector {
	return &MultiprotoEgressSelector{
		targets: make(map[string]*EgressTarget),
	}
}

// AddTarget registers an egress target
func (s *MultiprotoEgressSelector) AddTarget(target EgressTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets[target.TargetID] = &target
}

// UpdateMetrics updates target latency and packet loss
func (s *MultiprotoEgressSelector) UpdateMetrics(targetID string, latencyMs int, lossPercent float64, isActive bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	target, exists := s.targets[targetID]
	if !exists {
		return false
	}
	target.LatencyMs = latencyMs
	target.LossPercent = lossPercent
	target.IsActive = isActive
	return true
}

// SelectBestEgress picks highest scoring active target (composite score of weight, latency, loss)
func (s *MultiprotoEgressSelector) SelectBestEgress(preferredProto OutboundEgressProtocol) (*EgressTarget, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var bestTarget *EgressTarget
	bestScore := -1e9

	for _, t := range s.targets {
		if !t.IsActive {
			continue
		}
		// Score formula: Weight * 10 - LatencyMs - (LossPercent * 20) + (PreferredProto bonus: +50)
		score := float64(t.Weight*10) - float64(t.LatencyMs) - (t.LossPercent * 20.0)
		if preferredProto != "" && t.Protocol == preferredProto {
			score += 50.0
		}

		if score > bestScore {
			bestScore = score
			bestTarget = t
		}
	}

	if bestTarget == nil {
		return nil, errors.New("no active egress target available")
	}

	return bestTarget, nil
}
