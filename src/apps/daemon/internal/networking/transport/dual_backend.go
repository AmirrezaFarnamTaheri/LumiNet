package transport

import (
	"sync"
)

type BackendEngineType string

const (
	EngineKcpRawSocket    BackendEngineType = "kcp_raw_socket"
	EngineViolatedTcpQuic BackendEngineType = "violated_tcp_quic"
	EngineFallback        BackendEngineType = "fallback_standard"
)

type EngineHealth struct {
	RttMs                uint32
	PacketLossRate       float32
	ConsecutiveFailures  uint32
	IsAlive              bool
	TotalBytesTransacted uint64
}

type DualBackendController struct {
	mu           sync.RWMutex
	engines      map[BackendEngineType]*EngineHealth
	activeEngine BackendEngineType
}

func NewDualBackendController() *DualBackendController {
	c := &DualBackendController{
		engines:      make(map[BackendEngineType]*EngineHealth),
		activeEngine: EngineKcpRawSocket,
	}
	c.engines[EngineKcpRawSocket] = &EngineHealth{RttMs: 100, PacketLossRate: 0.0, IsAlive: true}
	c.engines[EngineViolatedTcpQuic] = &EngineHealth{RttMs: 100, PacketLossRate: 0.0, IsAlive: true}
	c.engines[EngineFallback] = &EngineHealth{RttMs: 100, PacketLossRate: 0.0, IsAlive: true}
	return c
}

func (c *DualBackendController) RecordMetrics(engine BackendEngineType, rttMs uint32, lossRate float32, success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	h, ok := c.engines[engine]
	if !ok {
		return
	}
	h.RttMs = rttMs
	h.PacketLossRate = lossRate
	if success {
		h.ConsecutiveFailures = 0
		h.IsAlive = true
	} else {
		h.ConsecutiveFailures++
		if h.ConsecutiveFailures >= 3 {
			h.IsAlive = false
		}
	}
}

func (c *DualBackendController) SelectEngine() BackendEngineType {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if h, ok := c.engines[c.activeEngine]; ok && h.IsAlive {
		return c.activeEngine
	}

	for _, eng := range []BackendEngineType{EngineKcpRawSocket, EngineViolatedTcpQuic, EngineFallback} {
		if h, ok := c.engines[eng]; ok && h.IsAlive {
			return eng
		}
	}

	return EngineFallback
}

func (c *DualBackendController) SelectByRttRace() BackendEngineType {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var bestEng BackendEngineType = EngineFallback
	var lowestScore float32 = 1e9

	for eng, h := range c.engines {
		if h.IsAlive {
			score := float32(h.RttMs) * (1.0 + h.PacketLossRate*2.0)
			if score < lowestScore {
				lowestScore = score
				bestEng = eng
			}
		}
	}
	return bestEng
}
