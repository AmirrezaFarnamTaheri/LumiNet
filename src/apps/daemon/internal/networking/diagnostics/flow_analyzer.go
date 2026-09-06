package diagnostics

import (
	"bytes"
	"net"
	"sync"
	"time"
)

type IdentifiedProtocol int

const (
	ProtocolUnknown IdentifiedProtocol = iota
	ProtocolTLS
	ProtocolHTTP
	ProtocolSSH
	ProtocolWireGuard
	ProtocolQUIC
)

type FlowRecord struct {
	FlowID          uint64
	SrcAddr         *net.TCPAddr
	DstAddr         *net.TCPAddr
	Protocol        IdentifiedProtocol
	PacketsSent     uint64
	PacketsRecv     uint64
	BytesSent       uint64
	BytesRecv       uint64
	Retransmissions uint64
	StartTime       time.Time
	LastSeen        time.Time
}

func (f *FlowRecord) RetransmissionRate() float64 {
	if f.PacketsSent == 0 {
		return 0
	}
	return (float64(f.Retransmissions) / float64(f.PacketsSent)) * 100.0
}

type FlowAnalyzerEngine struct {
	flows      map[uint64]*FlowRecord
	nextFlowID uint64
	mu         sync.RWMutex
}

func NewFlowAnalyzerEngine() *FlowAnalyzerEngine {
	return &FlowAnalyzerEngine{
		flows:      make(map[uint64]*FlowRecord),
		nextFlowID: 1,
	}
}

func InspectPayload(payload []byte) IdentifiedProtocol {
	if len(payload) == 0 {
		return ProtocolUnknown
	}
	// TLS ClientHello (0x16 0x03)
	if len(payload) >= 3 && payload[0] == 0x16 && payload[1] == 0x03 {
		return ProtocolTLS
	}
	// HTTP
	if bytes.HasPrefix(payload, []byte("GET ")) ||
		bytes.HasPrefix(payload, []byte("POST ")) ||
		bytes.HasPrefix(payload, []byte("HTTP/1.")) ||
		bytes.HasPrefix(payload, []byte("CONNECT ")) {
		return ProtocolHTTP
	}
	// SSH
	if bytes.HasPrefix(payload, []byte("SSH-")) {
		return ProtocolSSH
	}
	// WireGuard Handshake (0x01 or 0x02 + 3 zeros)
	if len(payload) >= 4 && (payload[0] == 0x01 || payload[0] == 0x02) && bytes.Equal(payload[1:4], []byte{0, 0, 0}) {
		return ProtocolWireGuard
	}
	return ProtocolUnknown
}

func (e *FlowAnalyzerEngine) RegisterFlow(src, dst *net.TCPAddr, initialPayload []byte) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()

	fid := e.nextFlowID
	e.nextFlowID++

	proto := InspectPayload(initialPayload)
	now := time.Now()

	e.flows[fid] = &FlowRecord{
		FlowID:          fid,
		SrcAddr:         src,
		DstAddr:         dst,
		Protocol:        proto,
		PacketsSent:     1,
		BytesSent:       uint64(len(initialPayload)),
		StartTime:       now,
		LastSeen:        now,
	}
	return fid
}

func (e *FlowAnalyzerEngine) RecordPacket(flowID uint64, bytes uint64, isEgress, isRetransmission bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	f, ok := e.flows[flowID]
	if !ok {
		return false
	}
	f.LastSeen = time.Now()
	if isEgress {
		f.PacketsSent++
		f.BytesSent += bytes
		if isRetransmission {
			f.Retransmissions++
		}
	} else {
		f.PacketsRecv++
		f.BytesRecv += bytes
	}
	return true
}

func (e *FlowAnalyzerEngine) GetFlow(flowID uint64) (*FlowRecord, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	f, ok := e.flows[flowID]
	if !ok {
		return nil, false
	}
	copy := *f
	return &copy, true
}

func (e *FlowAnalyzerEngine) DetectAnomalies(maxRetransmissionRate float64) []uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var anomalies []uint64
	for id, f := range e.flows {
		if f.RetransmissionRate() > maxRetransmissionRate {
			anomalies = append(anomalies, id)
		}
	}
	return anomalies
}
