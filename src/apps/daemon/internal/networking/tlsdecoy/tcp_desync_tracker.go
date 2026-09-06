// Package tlsdecoy provides TCP three-way handshake tracking and out-of-window
// desync injection calculations for DPI evasion.
// Originates from SNI-Spoofing-Go-main and adapted for LumiNet.

package tlsdecoy

import (
	"errors"
	"fmt"
	"sync"
)

// ConnID uniquely identifies a TCP connection 4-tuple.
type ConnID struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// HandshakePhase represents the progression of the TCP 3-way handshake.
type HandshakePhase int

const (
	PhaseInitial HandshakePhase = iota
	PhaseSynSent
	PhaseSynAckReceived
	PhaseHandshakeComplete
	PhaseDecoyInjected
	PhaseDecoyAcknowledged
	PhaseTerminated
)

// OutboundAction describes the action needed after processing an outbound packet.
type OutboundAction struct {
	ScheduleDecoy bool
	DecoySeq      uint32
	NewIdent      uint16
}

// InboundAction describes the outcome after processing an inbound packet.
type InboundAction struct {
	DecoyAcknowledged bool
}

// TcpDesyncTracker tracks TCP connection state to precisely time decoy injection.
type TcpDesyncTracker struct {
	mu          sync.Mutex
	ID          ConnID
	SynSeq      int64
	SynAckSeq   int64
	Phase       HandshakePhase
	FakeSent    bool
	SchFakeSent bool
}

// NewTcpDesyncTracker initializes a new tracker for a connection.
func NewTcpDesyncTracker(srcIP, dstIP string, srcPort, dstPort uint16) *TcpDesyncTracker {
	return &TcpDesyncTracker{
		ID: ConnID{
			SrcIP:   srcIP,
			SrcPort: srcPort,
			DstIP:   dstIP,
			DstPort: dstPort,
		},
		SynSeq:    -1,
		SynAckSeq: -1,
		Phase:     PhaseInitial,
	}
}

// ProcessOutbound handles client-originated outbound packets.
func (t *TcpDesyncTracker) ProcessOutbound(seq, ack uint32, isSYN, isACK, isRST, isFIN bool, payloadLen int, currIdent uint16, fakeLen int) (*OutboundAction, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Phase == PhaseDecoyInjected || t.Phase == PhaseDecoyAcknowledged {
		return &OutboundAction{}, nil
	}

	// 1. Outbound SYN: SYN=1, ACK=0, payload=0
	if isSYN && !isACK && !isRST && !isFIN && payloadLen == 0 {
		if ack != 0 {
			t.Phase = PhaseTerminated
			return nil, errors.New("outbound SYN ack number is not zero")
		}
		if t.SynSeq != -1 && t.SynSeq != int64(seq) {
			t.Phase = PhaseTerminated
			return nil, fmt.Errorf("outbound SYN seq mismatch: %d != %d", seq, t.SynSeq)
		}
		t.SynSeq = int64(seq)
		t.Phase = PhaseSynSent
		return &OutboundAction{}, nil
	}

	// 2. Outbound ACK completing handshake: SYN=0, ACK=1, payload=0
	if isACK && !isSYN && !isRST && !isFIN && payloadLen == 0 {
		expectedSeq := uint32((uint32(t.SynSeq) + 1) & 0xffffffff)
		if t.SynSeq == -1 || seq != expectedSeq {
			t.Phase = PhaseTerminated
			return nil, fmt.Errorf("outbound ACK seq mismatch: %d != %d", seq, expectedSeq)
		}
		expectedAck := uint32((uint32(t.SynAckSeq) + 1) & 0xffffffff)
		if t.SynAckSeq == -1 || ack != expectedAck {
			t.Phase = PhaseTerminated
			return nil, fmt.Errorf("outbound ACK ack mismatch: %d != %d", ack, expectedAck)
		}

		t.SchFakeSent = true
		t.Phase = PhaseHandshakeComplete

		// Out-of-window sequence formula: (SynSeq + 1 - fakeLen) & 0xFFFFFFFF
		decoySeq := (uint32(t.SynSeq) + 1 - uint32(fakeLen)) & 0xffffffff
		newIdent := (currIdent + 1) & 0xffff
		t.FakeSent = true
		t.Phase = PhaseDecoyInjected

		return &OutboundAction{
			ScheduleDecoy: true,
			DecoySeq:      decoySeq,
			NewIdent:      newIdent,
		}, nil
	}

	t.Phase = PhaseTerminated
	return nil, errors.New("unexpected outbound packet during handshake")
}

// ProcessInbound handles remote-server-originated inbound packets.
func (t *TcpDesyncTracker) ProcessInbound(seq, ack uint32, isSYN, isACK, isRST, isFIN bool, payloadLen int) (*InboundAction, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.SynSeq == -1 {
		t.Phase = PhaseTerminated
		return nil, errors.New("unexpected inbound packet before outbound SYN")
	}

	// 1. Inbound SYN-ACK: SYN=1, ACK=1, payload=0
	if isSYN && isACK && !isRST && !isFIN && payloadLen == 0 {
		expectedAck := uint32((uint32(t.SynSeq) + 1) & 0xffffffff)
		if ack != expectedAck {
			t.Phase = PhaseTerminated
			return nil, fmt.Errorf("inbound SYN-ACK ack mismatch: %d != %d", ack, expectedAck)
		}
		if t.SynAckSeq != -1 && t.SynAckSeq != int64(seq) {
			t.Phase = PhaseTerminated
			return nil, fmt.Errorf("inbound SYN-ACK seq change: %d != %d", seq, t.SynAckSeq)
		}
		t.SynAckSeq = int64(seq)
		t.Phase = PhaseSynAckReceived
		return &InboundAction{}, nil
	}

	// 2. Inbound ACK for decoy or post-handshake: ACK=1, SYN=0, payload=0
	if isACK && !isSYN && !isRST && !isFIN && payloadLen == 0 && (t.FakeSent || t.Phase == PhaseDecoyInjected) {
		expectedSeq := uint32((uint32(t.SynAckSeq) + 1) & 0xffffffff)
		if t.SynAckSeq == -1 || seq != expectedSeq {
			t.Phase = PhaseTerminated
			return nil, fmt.Errorf("inbound ACK seq mismatch: %d != %d", seq, expectedSeq)
		}
		expectedAck := uint32((uint32(t.SynSeq) + 1) & 0xffffffff)
		if ack != expectedAck {
			t.Phase = PhaseTerminated
			return nil, fmt.Errorf("inbound ACK ack mismatch: %d != %d", ack, expectedAck)
		}

		t.Phase = PhaseDecoyAcknowledged
		return &InboundAction{DecoyAcknowledged: true}, nil
	}

	t.Phase = PhaseTerminated
	return nil, errors.New("unexpected inbound packet")
}
