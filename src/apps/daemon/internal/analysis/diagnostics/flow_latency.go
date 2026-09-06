package diagnostics

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// FNV-1a 64-bit constants
	fnvOffsetBasis uint64 = 14695981039346656037
	fnvPrime       uint64 = 1099511628211
)

// FNV1aHash computes the 64-bit Fowler-Noll-Vo FNV-1a hash of a byte slice.
func FNV1aHash(s []byte) uint64 {
	h := fnvOffsetBasis
	for _, b := range s {
		h ^= uint64(b)
		h *= fnvPrime
	}
	return h
}

// ComputeFlowHash calculates a symmetrical 4-tuple flow hash where forward and reverse
// directions map to the identical bucket.
func ComputeFlowHash(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) uint64 {
	src16 := srcIP.To16()
	if src16 == nil {
		src16 = net.IPv6zero
	}
	dst16 := dstIP.To16()
	if dst16 == nil {
		dst16 = net.IPv6zero
	}

	bufSrc := make([]byte, 18)
	copy(bufSrc[0:16], src16)
	binary.BigEndian.PutUint16(bufSrc[16:18], srcPort)

	bufDst := make([]byte, 18)
	copy(bufDst[0:16], dst16)
	binary.BigEndian.PutUint16(bufDst[16:18], dstPort)

	hSrc := FNV1aHash(bufSrc)
	hDst := FNV1aHash(bufDst)

	return (hSrc + hDst) * fnvPrime
}

// TCPProbePacket represents a decoded TCP handshake event from eBPF TC classifier or packet stream.
type TCPProbePacket struct {
	SrcIP          net.IP
	SrcPort        uint16
	DstIP          net.IP
	DstPort        uint16
	SYN            bool
	ACK            bool
	TimestampNanos uint64
}

// FlowHash returns the 4-tuple symmetrical hash for this packet.
func (p *TCPProbePacket) FlowHash() uint64 {
	return ComputeFlowHash(p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
}

// UnmarshalTCPPacket deserializes a 48-byte eBPF perf event buffer into a TCPProbePacket.
func UnmarshalTCPPacket(in []byte) (*TCPProbePacket, error) {
	if len(in) < 48 {
		return nil, fmt.Errorf("insufficient buffer length: %d (expected 48)", len(in))
	}

	srcBytes := make([]byte, 16)
	dstBytes := make([]byte, 16)
	copy(srcBytes, in[0:16])
	copy(dstBytes, in[16:32])

	srcIP := parseIPFrom16(srcBytes)
	dstIP := parseIPFrom16(dstBytes)

	srcPort := binary.BigEndian.Uint16(in[32:34])
	dstPort := binary.BigEndian.Uint16(in[34:36])

	syn := in[36] == 1
	ack := in[37] == 1

	ts := binary.LittleEndian.Uint64(in[40:48])

	return &TCPProbePacket{
		SrcIP:          srcIP,
		SrcPort:        srcPort,
		DstIP:          dstIP,
		DstPort:        dstPort,
		SYN:            syn,
		ACK:            ack,
		TimestampNanos: ts,
	}, nil
}

func parseIPFrom16(b []byte) net.IP {
	// If IPv4-mapped (::ffff:a.b.c.d)
	if isIPv4Mapped(b) {
		return net.IPv4(b[12], b[13], b[14], b[15])
	}
	return net.IP(b)
}

func isIPv4Mapped(b []byte) bool {
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[10] == 0xff && b[11] == 0xff
}

// FlowLatencyStats stores aggregated RTT metrics across tracked connections.
type FlowLatencyStats struct {
	SampleCount uint64        `json:"sample_count"`
	MinRTT      time.Duration `json:"min_rtt"`
	MaxRTT      time.Duration `json:"max_rtt"`
	TotalRTT    time.Duration `json:"total_rtt"`
}

// Record observes a new RTT duration and updates aggregate statistics.
func (s *FlowLatencyStats) Record(rtt time.Duration) {
	s.SampleCount++
	s.TotalRTT += rtt
	if s.MinRTT == 0 || rtt < s.MinRTT {
		s.MinRTT = rtt
	}
	if rtt > s.MaxRTT {
		s.MaxRTT = rtt
	}
}

// AverageRTT returns the mean RTT or 0 if no samples have been collected.
func (s *FlowLatencyStats) AverageRTT() time.Duration {
	if s.SampleCount == 0 {
		return 0
	}
	return time.Duration(uint64(s.TotalRTT) / s.SampleCount)
}

// FlowLatencyTracker tracks in-flight TCP handshakes to observe round-trip latency.
type FlowLatencyTracker struct {
	mu       sync.RWMutex
	synTable map[uint64]uint64
	stats    FlowLatencyStats
}

// NewFlowLatencyTracker creates an initialized thread-safe tracker.
func NewFlowLatencyTracker() *FlowLatencyTracker {
	return &FlowLatencyTracker{
		synTable: make(map[uint64]uint64),
	}
}

// OnSYN registers an outgoing or incoming TCP SYN packet.
func (t *FlowLatencyTracker) OnSYN(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, tsNanos uint64) {
	key := ComputeFlowHash(srcIP, srcPort, dstIP, dstPort)
	t.mu.Lock()
	t.synTable[key] = tsNanos
	t.mu.Unlock()
}

// OnSYNACK records a received SYN-ACK packet, removes the in-flight state, and returns computed RTT.
func (t *FlowLatencyTracker) OnSYNACK(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, tsNanos uint64) (time.Duration, bool) {
	key := ComputeFlowHash(srcIP, srcPort, dstIP, dstPort)
	t.mu.Lock()
	defer t.mu.Unlock()

	synTs, exists := t.synTable[key]
	if !exists {
		return 0, false
	}
	delete(t.synTable, key)

	if tsNanos < synTs {
		return 0, false
	}
	rtt := time.Duration(tsNanos-synTs) * time.Nanosecond
	t.stats.Record(rtt)
	return rtt, true
}

// ProcessPacket inspects a TCPProbePacket and handles handshake transitions.
func (t *FlowLatencyTracker) ProcessPacket(pkt *TCPProbePacket) (time.Duration, bool) {
	if pkt.SYN && !pkt.ACK {
		t.OnSYN(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.TimestampNanos)
		return 0, false
	}
	if pkt.SYN && pkt.ACK {
		return t.OnSYNACK(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.TimestampNanos)
	}
	return 0, false
}

// PruneStale eliminates orphaned SYN entries older than maxAgeNanos.
func (t *FlowLatencyTracker) PruneStale(nowNanos, maxAgeNanos uint64) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	pruned := 0
	for key, ts := range t.synTable {
		if nowNanos > ts && (nowNanos-ts) > maxAgeNanos {
			delete(t.synTable, key)
			pruned++
		}
	}
	return pruned
}

// PendingCount returns the number of currently outstanding SYN handshakes.
func (t *FlowLatencyTracker) PendingCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.synTable)
}

// GetStats returns a copy of current latency statistics.
func (t *FlowLatencyTracker) GetStats() FlowLatencyStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.stats
}
