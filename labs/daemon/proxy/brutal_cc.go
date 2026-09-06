package proxy

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// BrutalCC — userspace port of Hysteria2's Brutal congestion controller
// Algorithm: CWND = bps * RTT * 2 / ackRate
//   ackRate = ackCount / (ackCount+lossCount)  [5-second sliding window]
//   ackRate clamped to [minAckRate, 1.0]
// Sources:
//   hysteria-master/core/internal/congestion/brutal/brutal.go
//   tcp-brutal-master/brutal.c  (kernel implementation for constants)
// ─────────────────────────────────────────────────────────────────────────────

const (
	brutalPktInfoSlots = 5              // sliding-window slot count (one per second)
	brutalMinSamples   = 50             // ignore rate estimate if fewer than 50 samples
	brutalMinAckRate   = 0.80           // floor ack rate at 80% to avoid overcorrection
	brutalCWNDMult     = 2.0            // congestion window multiplier (Hysteria default)
	brutalInitRateBps  = 1_000_000 * 10 // 10 Mbps default
	brutalInitCWNDGain = 20             // ×1/10 → 2.0× multiplier
)

// brutalPktInfo holds per-second ack/loss counts for the sliding window.
type brutalPktInfo struct {
	sec  int64
	acks uint64
	loss uint64
}

// BrutalCC implements a simple bandwidth-forcing congestion controller.
// It ignores loss-based back-off (unlike CUBIC/Reno) and instead compensates
// by scaling the send rate upward when acks indicate packet loss.
type BrutalCC struct {
	mu      sync.Mutex
	slots   [brutalPktInfoSlots]brutalPktInfo
	ackRate float64

	// configuration (set once, read-only after Start)
	targetBps int64 // desired send rate in bytes/sec
	cwndGain  int   // CWND gain in tenths (20 = 2.0×)

	// runtime statistics
	rttNs     atomic.Int64 // smoothed RTT in nanoseconds
	cwndBytes atomic.Int64
}

// NewBrutalCC creates a BrutalCC with the given target rate and CWND gain.
// targetBps: desired throughput in bytes per second.
// cwndGain:  CWND multiplier ×0.1 (e.g. 20 = 2.0×). Use 15–25 for typical links.
func NewBrutalCC(targetBps int64, cwndGain int) *BrutalCC {
	if targetBps <= 0 {
		targetBps = brutalInitRateBps
	}
	if cwndGain < 5 || cwndGain > 80 {
		cwndGain = brutalInitCWNDGain
	}
	b := &BrutalCC{
		targetBps: targetBps,
		cwndGain:  cwndGain,
		ackRate:   1.0,
	}
	b.rttNs.Store(int64(20 * time.Millisecond))
	b.updateCWND()
	return b
}

// SetRTT updates the smoothed RTT estimate. Call on each ACK.
func (b *BrutalCC) SetRTT(rtt time.Duration) {
	if rtt > 0 {
		b.rttNs.Store(int64(rtt))
		b.updateCWND()
	}
}

// OnAck records a batch of acknowledged packets. Call from your ACK handler.
func (b *BrutalCC) OnAck(count uint64) {
	b.onEvent(count, 0)
}

// OnLoss records a batch of lost packets. Call from your loss handler.
func (b *BrutalCC) OnLoss(count uint64) {
	b.onEvent(0, count)
}

// OnAckLoss records acks and losses from a single congestion event.
func (b *BrutalCC) OnAckLoss(acks, losses uint64) {
	b.onEvent(acks, losses)
}

// CongestionWindow returns the current congestion window in bytes.
func (b *BrutalCC) CongestionWindow() int64 {
	return b.cwndBytes.Load()
}

// EffectiveSendRate returns the send rate after loss compensation (bytes/sec).
// This is the actual rate to pace packets at.
func (b *BrutalCC) EffectiveSendRate() int64 {
	b.mu.Lock()
	ar := b.ackRate
	b.mu.Unlock()
	if ar <= 0 {
		ar = brutalMinAckRate
	}
	return int64(math.Ceil(float64(b.targetBps) / ar))
}

// onEvent records ack/loss counts into the sliding window and recalculates.
func (b *BrutalCC) onEvent(acks, losses uint64) {
	now := time.Now().Unix()
	slot := now % brutalPktInfoSlots

	b.mu.Lock()
	if b.slots[slot].sec == now {
		b.slots[slot].acks += acks
		b.slots[slot].loss += losses
	} else {
		b.slots[slot] = brutalPktInfo{sec: now, acks: acks, loss: losses}
	}
	b.recalcAckRateLocked(now)
	b.mu.Unlock()

	b.updateCWND()
}

// recalcAckRateLocked recalculates ackRate from the last 5-second window.
// Must be called with mu held.
func (b *BrutalCC) recalcAckRateLocked(nowSec int64) {
	minSec := nowSec - brutalPktInfoSlots
	var totalAcks, totalLoss uint64
	for _, s := range b.slots {
		if s.sec > minSec {
			totalAcks += s.acks
			totalLoss += s.loss
		}
	}
	total := totalAcks + totalLoss
	if total < brutalMinSamples {
		b.ackRate = 1.0 // not enough data — assume perfect
		return
	}
	rate := float64(totalAcks) / float64(total)
	if rate < brutalMinAckRate {
		rate = brutalMinAckRate
	}
	b.ackRate = rate
}

// updateCWND recomputes the congestion window from current rate + RTT.
// Formula: CWND = effectiveRate * RTT * cwndGain/10
func (b *BrutalCC) updateCWND() {
	rate := b.EffectiveSendRate()
	rttSec := float64(b.rttNs.Load()) / float64(time.Second)
	gain := float64(b.cwndGain) / 10.0
	cwnd := int64(float64(rate) * rttSec * gain)
	if cwnd < 10240 { // floor: at least 10 KiB
		cwnd = 10240
	}
	b.cwndBytes.Store(cwnd)
}

// ─────────────────────────────────────────────────────────────────────────────
// BrutalPacer — token-bucket pacing to spread packets over the send interval
// Source: hysteria-master/core/internal/congestion/common/pacer.go
// ─────────────────────────────────────────────────────────────────────────────

const (
	pacerMaxBurstPackets = 10
	pacerMinDelay        = time.Millisecond // minimum inter-packet gap
)

// BrutalPacer implements token-bucket pacing to smooth packet sends.
type BrutalPacer struct {
	mu              sync.Mutex
	budgetBytes     int64     // current token budget
	lastSentAt      time.Time // time of last packet send
	maxDatagramSize int64     // MTU / max datagram size
	getBandwidth    func() int64
}

// NewBrutalPacer creates a pacer. getBandwidth is called each time to get the
// current send rate in bytes/sec (so it can track BrutalCC dynamically).
func NewBrutalPacer(maxDatagramSize int64, getBandwidth func() int64) *BrutalPacer {
	return &BrutalPacer{
		budgetBytes:     pacerMaxBurstPackets * maxDatagramSize,
		maxDatagramSize: maxDatagramSize,
		getBandwidth:    getBandwidth,
	}
}

// TimeUntilSend returns how long to wait before the next packet can be sent.
// Returns 0 if a packet can be sent immediately.
func (p *BrutalPacer) TimeUntilSend() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.budgetBytes >= p.maxDatagramSize {
		return 0
	}
	bw := p.getBandwidth()
	if bw <= 0 {
		return pacerMinDelay
	}
	need := p.maxDatagramSize - p.budgetBytes // bytes needed
	// time = need / bandwidth (in seconds), converted to nanoseconds
	ns := need * int64(time.Second) / bw
	if ns < int64(pacerMinDelay) {
		ns = int64(pacerMinDelay)
	}
	return time.Duration(ns)
}

// OnPacketSent must be called after each packet is sent.
func (p *BrutalPacer) OnPacketSent(now time.Time, pktSize int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.accrueBudgetLocked(now)
	p.budgetBytes -= pktSize
	if p.budgetBytes < 0 {
		p.budgetBytes = 0
	}
	p.lastSentAt = now
}

// accrueBudgetLocked adds tokens earned since lastSentAt. Must be called with mu held.
func (p *BrutalPacer) accrueBudgetLocked(now time.Time) {
	if p.lastSentAt.IsZero() {
		p.budgetBytes = p.maxBurstSize()
		return
	}
	elapsed := now.Sub(p.lastSentAt)
	bw := p.getBandwidth()
	earned := bw * int64(elapsed) / int64(time.Second)
	p.budgetBytes += earned
	maxBurst := p.maxBurstSize()
	if p.budgetBytes > maxBurst {
		p.budgetBytes = maxBurst
	}
}

func (p *BrutalPacer) maxBurstSize() int64 {
	return pacerMaxBurstPackets * p.maxDatagramSize
}

// cryptoRandBytes fills b with cryptographically random bytes.
func cryptoRandBytes(b []byte) {
	_, _ = rand.Read(b)
}

// cryptoRandUint64 returns a cryptographically random uint64.
func cryptoRandUint64() uint64 {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return binary.BigEndian.Uint64(buf[:])
}
