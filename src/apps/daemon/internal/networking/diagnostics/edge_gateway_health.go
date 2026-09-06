package diagnostics

import (
	"strings"
	"sync"
)

type EdgeHealthState string

const (
	EdgeHealthHealthy  EdgeHealthState = "healthy"
	EdgeHealthDegraded EdgeHealthState = "degraded"
	EdgeHealthCritical EdgeHealthState = "critical"
	EdgeHealthDown     EdgeHealthState = "down"
)

type EdgeGatewayMetrics struct {
	GatewayID      string          `json:"gateway_id"`
	Endpoint       string          `json:"endpoint"`
	TotalRequests  uint64          `json:"total_requests"`
	FailedRequests uint64          `json:"failed_requests"`
	AvgLatencyMs   uint32          `json:"avg_latency_ms"`
	LoadFactor     float32         `json:"load_factor"`
	State          EdgeHealthState `json:"state"`
}

type EdgeGatewayHealthMeter struct {
	mu                 sync.RWMutex
	gateways           map[string]*EdgeGatewayMetrics
	failureThreshold   float32
	latencyThresholdMs uint32
}

func NewEdgeGatewayHealthMeter(failureThreshold float32, latencyThresholdMs uint32) *EdgeGatewayHealthMeter {
	if failureThreshold <= 0.0 || failureThreshold > 1.0 {
		failureThreshold = 0.2
	}
	return &EdgeGatewayHealthMeter{
		gateways:           make(map[string]*EdgeGatewayMetrics),
		failureThreshold:   failureThreshold,
		latencyThresholdMs: latencyThresholdMs,
	}
}

func (m *EdgeGatewayHealthMeter) RegisterGateway(gatewayID, endpoint string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cleanID := strings.TrimSpace(gatewayID)
	m.gateways[cleanID] = &EdgeGatewayMetrics{
		GatewayID:      cleanID,
		Endpoint:       strings.TrimSpace(endpoint),
		TotalRequests:  0,
		FailedRequests: 0,
		AvgLatencyMs:   0,
		LoadFactor:     0.0,
		State:          EdgeHealthHealthy,
	}
}

func (m *EdgeGatewayHealthMeter) RecordRequest(gatewayID string, latencyMs uint32, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	gw, ok := m.gateways[gatewayID]
	if !ok {
		return
	}

	gw.TotalRequests++
	if !success {
		gw.FailedRequests++
	}

	if gw.AvgLatencyMs == 0 {
		gw.AvgLatencyMs = latencyMs
	} else {
		gw.AvgLatencyMs = (gw.AvgLatencyMs*7 + latencyMs*3) / 10
	}

	failRate := float32(gw.FailedRequests) / float32(gw.TotalRequests)
	latencyRatio := float32(gw.AvgLatencyMs) / float32(m.latencyThresholdMs)
	if latencyRatio > 1.0 {
		latencyRatio = 1.0
	}

	gw.LoadFactor = failRate*0.6 + latencyRatio*0.4
	if gw.LoadFactor > 1.0 {
		gw.LoadFactor = 1.0
	}

	if failRate > m.failureThreshold*2.0 {
		gw.State = EdgeHealthDown
	} else if failRate > m.failureThreshold {
		gw.State = EdgeHealthCritical
	} else if gw.AvgLatencyMs > m.latencyThresholdMs {
		gw.State = EdgeHealthDegraded
	} else {
		gw.State = EdgeHealthHealthy
	}
}

func (m *EdgeGatewayHealthMeter) GetMetrics(gatewayID string) *EdgeGatewayMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	gw, ok := m.gateways[gatewayID]
	if !ok {
		return nil
	}
	cp := *gw
	return &cp
}

func (m *EdgeGatewayHealthMeter) SelectBestGateway() *EdgeGatewayMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var best *EdgeGatewayMetrics
	for _, gw := range m.gateways {
		if gw.State == EdgeHealthDown {
			continue
		}
		if best == nil || gw.LoadFactor < best.LoadFactor {
			best = gw
		}
	}
	if best == nil {
		return nil
	}
	cp := *best
	return &cp
}
