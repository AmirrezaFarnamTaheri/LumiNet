package p2p

import (
	"sync"
	"time"
)

const alpha = 0.125 // EWMA smoothing factor (RFC 6298)

// LinkMetrics maintains exponential weighted moving average (EWMA) RTT and loss scoring.
type LinkMetrics struct {
	mu         sync.RWMutex
	EWMARttMs  float64
	LossRate   float64
	Score      float64
	LastUpdate time.Time
}

// NewLinkMetrics creates LinkMetrics initialized with initial RTT.
func NewLinkMetrics(initialRttMs float64) *LinkMetrics {
	lm := &LinkMetrics{
		EWMARttMs:  initialRttMs,
		LossRate:   0.0,
		LastUpdate: time.Now(),
	}
	lm.recalculateScore()
	return lm
}

// UpdateRTT incorporates a new latency sample into the EWMA.
func (lm *LinkMetrics) UpdateRTT(sampleRttMs float64) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.EWMARttMs == 0 {
		lm.EWMARttMs = sampleRttMs
	} else {
		lm.EWMARttMs = alpha*sampleRttMs + (1-alpha)*lm.EWMARttMs
	}
	lm.LastUpdate = time.Now()
	lm.recalculateScore()
}

// UpdateLoss incorporates packet loss measurement (0.0 to 1.0).
func (lm *LinkMetrics) UpdateLoss(lossRate float64) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lossRate < 0 {
		lossRate = 0
	}
	if lossRate > 1 {
		lossRate = 1
	}
	lm.LossRate = lossRate
	lm.recalculateScore()
}

func (lm *LinkMetrics) recalculateScore() {
	if lm.EWMARttMs <= 0 {
		lm.Score = 0
		return
	}
	// Score formula: (1000 / RTT) * (1 - LossRate)
	lm.Score = (1000.0 / lm.EWMARttMs) * (1.0 - lm.LossRate)
}
