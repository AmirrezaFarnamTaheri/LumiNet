package transport

import (
	"math"
	"sync"
	"time"
)

type BrutalPacer struct {
	mu           sync.Mutex
	targetBps    uint64
	minBps       uint64
	maxBps       uint64
	packetLoss   float64
	ackRateBps   uint64
	lastUpdate   time.Time
}

func NewBrutalPacer(targetBps, minBps, maxBps uint64) *BrutalPacer {
	return &BrutalPacer{
		targetBps:  targetBps,
		minBps:     minBps,
		maxBps:     maxBps,
		lastUpdate: time.Now(),
	}
}

func (p *BrutalPacer) UpdateAckFeedback(ackRateBps uint64, lossRatio float64) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ackRateBps = ackRateBps
	p.packetLoss = math.Max(0.0, math.Min(1.0, lossRatio))

	// R = AckRate * (1 + loss)
	compensation := float64(ackRateBps) * (1.0 + p.packetLoss)
	newRate := uint64(compensation)
	if newRate < p.minBps {
		newRate = p.minBps
	}
	if newRate > p.maxBps {
		newRate = p.maxBps
	}
	p.targetBps = newRate
	p.lastUpdate = time.Now()
	return p.targetBps
}

func (p *BrutalPacer) GetPacingDelay(packetBytes int) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.targetBps == 0 {
		return 0
	}
	nanos := float64(packetBytes*8) * 1e9 / float64(p.targetBps)
	return time.Duration(nanos)
}

type SalamanderObfuscator struct {
	key [32]byte
	pos int
}

func NewSalamanderObfuscator(key [32]byte) *SalamanderObfuscator {
	return &SalamanderObfuscator{key: key, pos: 0}
}

func (o *SalamanderObfuscator) ApplyInPlace(data []byte) {
	for i := range data {
		data[i] ^= o.key[o.pos%32]
		o.pos++
	}
}
