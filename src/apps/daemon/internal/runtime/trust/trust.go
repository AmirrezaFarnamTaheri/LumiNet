package trust

import (
	"sync"
	"time"
)

// Metrics tracks cognitive trust and reputation for P2P mesh egress nodes.
type Metrics struct {
	RTT         time.Duration
	PacketLoss  float64
	SuccessRate float64
	UserRating  float64 // 0.0 to 5.0 scale
	TotalDials  int
	LastSeen    time.Time
}

// Store manages P2P decentralized trust/reputation rating tables.
type Store struct {
	mu      sync.RWMutex
	metrics map[string]*Metrics
}

var globalStore = &Store{
	metrics: make(map[string]*Metrics),
}

// GetStore returns the global cognitive trust stack.
func GetStore() *Store {
	return globalStore
}

// RecordMetric updates the RTT, success, and packet loss for a node.
func (cs *Store) RecordMetric(nodeID string, rtt time.Duration, success bool, packetLoss float64) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	m, exists := cs.metrics[nodeID]
	if !exists {
		m = &Metrics{
			UserRating: 5.0, // Default perfect rating
		}
		cs.metrics[nodeID] = m
	}

	m.TotalDials++
	m.LastSeen = time.Now()
	m.RTT = (m.RTT*9 + rtt) / 10 // Exponential moving average

	statusVal := 0.0
	if success {
		statusVal = 1.0
	}
	m.SuccessRate = (m.SuccessRate*9 + statusVal) / 10
	m.PacketLoss = (m.PacketLoss*9 + packetLoss) / 10
}

// SubmitRating records user rating feedback for a residential egress node.
func (cs *Store) SubmitRating(nodeID string, rating float64) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	m, exists := cs.metrics[nodeID]
	if !exists {
		m = &Metrics{
			LastSeen: time.Now(),
		}
		cs.metrics[nodeID] = m
	}
	if m.UserRating == 0.0 {
		m.UserRating = rating
	} else {
		m.UserRating = (m.UserRating*4 + rating) / 5
	}
}

// ComputeTrustScore returns a normalized trust rating (0.0 to 1.0) for routing decisions.
func (cs *Store) ComputeTrustScore(nodeID string) float64 {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	m, exists := cs.metrics[nodeID]
	if !exists {
		return 0.8 // Baseline initial trust
	}

	return computeTrustScore(m)
}

// SnapshotScores returns trust scores for nodes that have actual observed or
// user-rated state. Unknown baseline nodes are intentionally absent so callers
// cannot mistake default trust for observed runtime state.
func (cs *Store) SnapshotScores() map[string]float64 {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	out := make(map[string]float64, len(cs.metrics))
	for nodeID, metrics := range cs.metrics {
		out[nodeID] = computeTrustScore(metrics)
	}
	return out
}

func computeTrustScore(m *Metrics) float64 {
	rttScore := 1.0
	if m.RTT > 0 {
		rttMs := float64(m.RTT.Milliseconds())
		if rttMs > 1000 {
			rttScore = 0.1
		} else {
			rttScore = 1.0 - (rttMs/1000.0)*0.9
		}
	}

	lossScore := 1.0 - m.PacketLoss
	successScore := m.SuccessRate
	ratingScore := m.UserRating / 5.0
	score := (rttScore * 0.2) + (lossScore * 0.2) + (successScore * 0.3) + (ratingScore * 0.3)
	if score < 0.0 {
		return 0.0
	}
	if score > 1.0 {
		return 1.0
	}
	return score
}
