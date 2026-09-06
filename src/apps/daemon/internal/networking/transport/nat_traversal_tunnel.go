package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// P2PNatType characterizes NAT traversal behavior
type P2PNatType int

const (
	P2PNatOpenInternet P2PNatType = iota
	P2PNatFullCone
	P2PNatRestrictedCone
	P2PNatPortRestrictedCone
	P2PNatSymmetric
)

// P2PPunchState tracks hole punching state
type P2PPunchState int

const (
	PunchStateInitial P2PPunchState = iota
	PunchStateProbing
	PunchStateEstablished
	PunchStateFallbackRelay
)

// PeerEndpointCandidate represents candidates exchanged via rendezvous
type PeerEndpointCandidate struct {
	PeerID            string
	LocalEndpoint     *net.UDPAddr
	ReflexiveEndpoint *net.UDPAddr
	NatType           P2PNatType
}

// NatTraversalTunnel manages NAT traversal and P2P punching
type NatTraversalTunnel struct {
	mu          sync.RWMutex
	LocalPeerID string
	LocalNat    P2PNatType
	Peers       map[string]P2PPunchState
	Magic       uint32
}

const DefaultPunchMagic uint32 = 0x564E5431 // "VNT1"

// NewNatTraversalTunnel creates a NAT traversal controller
func NewNatTraversalTunnel(localID string, nat P2PNatType) *NatTraversalTunnel {
	return &NatTraversalTunnel{
		LocalPeerID: localID,
		LocalNat:    nat,
		Peers:       make(map[string]P2PPunchState),
		Magic:       DefaultPunchMagic,
	}
}

// CanDirectHolePunch checks if two NAT topologies can punch directly
func CanDirectHolePunch(a, b P2PNatType) bool {
	if a == P2PNatSymmetric && b == P2PNatSymmetric {
		return false
	}
	if (a == P2PNatPortRestrictedCone && b == P2PNatSymmetric) ||
		(a == P2PNatSymmetric && b == P2PNatPortRestrictedCone) {
		return false
	}
	return true
}

// CraftPunchPacket creates a serialized UDP punch probe packet
func (t *NatTraversalTunnel) CraftPunchPacket(seq uint32) []byte {
	buf := new(bytes.Buffer)
	var magicBytes [4]byte
	binary.BigEndian.PutUint32(magicBytes[:], t.Magic)
	buf.Write(magicBytes[:])

	var seqBytes [4]byte
	binary.BigEndian.PutUint32(seqBytes[:], seq)
	buf.Write(seqBytes[:])

	idBytes := []byte(t.LocalPeerID)
	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], uint16(len(idBytes)))
	buf.Write(lenBytes[:])
	buf.Write(idBytes)

	return buf.Bytes()
}

// ParsePunchPacket deserializes and verifies punch packet
func (t *NatTraversalTunnel) ParsePunchPacket(data []byte) (uint32, string, error) {
	if len(data) < 10 {
		return 0, "", errors.New("packet too short")
	}

	magic := binary.BigEndian.Uint32(data[0:4])
	if magic != t.Magic {
		return 0, "", errors.New("invalid magic value")
	}

	seq := binary.BigEndian.Uint32(data[4:8])
	idLen := int(binary.BigEndian.Uint16(data[8:10]))
	if len(data) < 10+idLen {
		return 0, "", errors.New("incomplete peer id in packet")
	}

	peerID := string(data[10 : 10+idLen])
	return seq, peerID, nil
}

// InitiatePeerPunch evaluates candidate and transitions state
func (t *NatTraversalTunnel) InitiatePeerPunch(cand *PeerEndpointCandidate) P2PPunchState {
	t.mu.Lock()
	defer t.mu.Unlock()

	if CanDirectHolePunch(t.LocalNat, cand.NatType) {
		t.Peers[cand.PeerID] = PunchStateProbing
		return PunchStateProbing
	}

	t.Peers[cand.PeerID] = PunchStateFallbackRelay
	return PunchStateFallbackRelay
}

// MarkEstablished transitions peer state to established
func (t *NatTraversalTunnel) MarkEstablished(peerID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.Peers[peerID]; ok {
		t.Peers[peerID] = PunchStateEstablished
		return true
	}
	return false
}
