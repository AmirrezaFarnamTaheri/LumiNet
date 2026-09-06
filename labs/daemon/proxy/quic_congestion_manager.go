package proxy

import (
	"sync"
)

type CongestionAlgorithm string

const (
	CongestionBBR   CongestionAlgorithm = "bbr"
	CongestionCubic CongestionAlgorithm = "cubic"
	CongestionReno  CongestionAlgorithm = "reno"
)

type QUICCongestionManager struct {
	mu        sync.RWMutex
	algorithm CongestionAlgorithm
	paceRate  int
}

func NewQUICCongestionManager() *QUICCongestionManager {
	return &QUICCongestionManager{
		algorithm: CongestionBBR,
		paceRate:  1000,
	}
}

func (m *QUICCongestionManager) SetAlgorithm(algo CongestionAlgorithm) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.algorithm = algo
}

func (m *QUICCongestionManager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]interface{}{
		"algorithm": string(m.algorithm),
		"pace_rate": m.paceRate,
	}
}
