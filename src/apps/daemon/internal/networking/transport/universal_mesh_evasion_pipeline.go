package transport

import (
	"sync"
)

// PipelineTransportTier represents escalation level
type PipelineTransportTier int

const (
	TierDirectMesh PipelineTransportTier = iota
	TierHolePunchedMesh
	TierDpiEvadedMesh
	TierStealthBridgeFallback
)

// PipelineMetrics tracks operational statistics
type PipelineMetrics struct {
	PacketsProcessed uint64
	ModeSwitches     uint32
	CurrentTier      PipelineTransportTier
}

// UniversalMeshEvasionPipeline synthesizes Mesh + NAT Punching + DPI Evasion + Stealth Relay
type UniversalMeshEvasionPipeline struct {
	mu                sync.RWMutex
	PeerID            string
	ConsecutiveErrors uint32
	Metrics           PipelineMetrics
}

const PipelineEscalationThreshold uint32 = 3

// NewUniversalMeshEvasionPipeline creates an integrated pipeline
func NewUniversalMeshEvasionPipeline(peerID string) *UniversalMeshEvasionPipeline {
	return &UniversalMeshEvasionPipeline{
		PeerID: peerID,
		Metrics: PipelineMetrics{
			CurrentTier: TierDirectMesh,
		},
	}
}

// ProcessOutboundFrame processes frame according to active escalation tier
func (p *UniversalMeshEvasionPipeline) ProcessOutboundFrame(frame []byte) [][]byte {
	p.mu.Lock()
	p.Metrics.PacketsProcessed++
	tier := p.Metrics.CurrentTier
	p.mu.Unlock()

	switch tier {
	case TierDirectMesh, TierHolePunchedMesh:
		return [][]byte{frame}

	case TierDpiEvadedMesh:
		if len(frame) > 8 {
			mid := len(frame) / 2
			return [][]byte{frame[:mid], frame[mid:]}
		}
		return [][]byte{frame}

	case TierStealthBridgeFallback:
		wrapped := append([]byte("STH:"), frame...)
		return [][]byte{wrapped}

	default:
		return [][]byte{frame}
	}
}

// ReportFailure escalates tier after consecutive failure threshold
func (p *UniversalMeshEvasionPipeline) ReportFailure() PipelineTransportTier {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ConsecutiveErrors++
	if p.ConsecutiveErrors >= PipelineEscalationThreshold {
		p.ConsecutiveErrors = 0
		var nextTier PipelineTransportTier
		switch p.Metrics.CurrentTier {
		case TierDirectMesh:
			nextTier = TierHolePunchedMesh
		case TierHolePunchedMesh:
			nextTier = TierDpiEvadedMesh
		case TierDpiEvadedMesh:
			nextTier = TierStealthBridgeFallback
		case TierStealthBridgeFallback:
			nextTier = TierStealthBridgeFallback
		}

		if nextTier != p.Metrics.CurrentTier {
			p.Metrics.CurrentTier = nextTier
			p.Metrics.ModeSwitches++
		}
	}

	return p.Metrics.CurrentTier
}

// ReportSuccess resets consecutive errors
func (p *UniversalMeshEvasionPipeline) ReportSuccess() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ConsecutiveErrors = 0
}

// GetMetrics returns snapshot of pipeline metrics
func (p *UniversalMeshEvasionPipeline) GetMetrics() PipelineMetrics {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Metrics
}
