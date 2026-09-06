package safety

import (
	"sync"
)

type GatewayState int

const (
	GatewayOnline GatewayState = iota
	GatewayDegraded
	GatewayOffline
)

type GatewayMetric struct {
	GatewayIP       string       `json:"gateway_ip"`
	LatencyMs       float64      `json:"latency_ms"`
	PacketLossRatio float64      `json:"packet_loss_ratio"`
	State           GatewayState `json:"state"`
}

type GatewayHealthMonitor struct {
	mu            sync.RWMutex
	gateways      map[string]*GatewayMetric
	lossDegraded  float64
	lossOffline   float64
}

func NewGatewayHealthMonitor() *GatewayHealthMonitor {
	return &GatewayHealthMonitor{
		gateways:     make(map[string]*GatewayMetric),
		lossDegraded: 0.20,
		lossOffline:  0.50,
	}
}

func (m *GatewayHealthMonitor) RegisterGateway(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gateways[ip] = &GatewayMetric{
		GatewayIP:       ip,
		LatencyMs:       0.0,
		PacketLossRatio: 0.0,
		State:           GatewayOnline,
	}
}

func (m *GatewayHealthMonitor) RecordProbe(ip string, latencyMs, loss float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if gw, exists := m.gateways[ip]; exists {
		gw.LatencyMs = latencyMs
		gw.PacketLossRatio = loss
		if loss >= m.lossOffline {
			gw.State = GatewayOffline
		} else if loss >= m.lossDegraded {
			gw.State = GatewayDegraded
		} else {
			gw.State = GatewayOnline
		}
	}
}

func (m *GatewayHealthMonitor) SelectActiveGateway(primary, backup string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if gw, exists := m.gateways[primary]; exists && gw.State == GatewayOnline {
		return primary
	}
	if gw, exists := m.gateways[backup]; exists && gw.State != GatewayOffline {
		return backup
	}
	return primary
}
