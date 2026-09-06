package proxy

import (
	"errors"
	"sync"
)

type OutboundNodeRecord struct {
	NodeID        string  `json:"node_id"`
	Protocol      string  `json:"protocol"`
	Endpoint      string  `json:"endpoint"`
	EwmaLatencyMs float64 `json:"ewma_latency_ms"`
	TotalProbes   uint64  `json:"total_probes"`
}

type LatencyRaceSelector struct {
	mu    sync.RWMutex
	nodes map[string]*OutboundNodeRecord
}

func NewLatencyRaceSelector() *LatencyRaceSelector {
	return &LatencyRaceSelector{
		nodes: make(map[string]*OutboundNodeRecord),
	}
}

func (s *LatencyRaceSelector) RegisterNode(id, proto, endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nodes[id] = &OutboundNodeRecord{
		NodeID:        id,
		Protocol:      proto,
		Endpoint:      endpoint,
		EwmaLatencyMs: 0.0,
		TotalProbes:   0,
	}
}

func (s *LatencyRaceSelector) RecordProbe(id string, latencyMs float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if node, exists := s.nodes[id]; exists {
		node.TotalProbes++
		if node.EwmaLatencyMs == 0.0 {
			node.EwmaLatencyMs = latencyMs
		} else {
			node.EwmaLatencyMs = 0.7*node.EwmaLatencyMs + 0.3*latencyMs
		}
	}
}

func (s *LatencyRaceSelector) SelectFastest() (*OutboundNodeRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var best *OutboundNodeRecord
	minLatency := 1e9

	for _, node := range s.nodes {
		if node.EwmaLatencyMs > 0.0 && node.EwmaLatencyMs < minLatency {
			minLatency = node.EwmaLatencyMs
			best = node
		}
	}

	if best == nil {
		return nil, errors.New("no probed nodes available")
	}
	return best, nil
}
