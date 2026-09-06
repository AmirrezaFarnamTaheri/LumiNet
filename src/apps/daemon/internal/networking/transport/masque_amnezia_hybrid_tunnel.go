package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
)

// MasqueAmneziaHybridConfig configures the hybrid MASQUE + Amnezia evasion tunnel
type MasqueAmneziaHybridConfig struct {
	ContextID      uint64
	AmneziaParams  AmneziaObfsParameters
	EnableEvasion  bool
	JunkBufferSize int
}

// MasqueAmneziaHybridTunnel synthesizes MASQUE (RFC 9298) with AmneziaWG obfuscation headers
type MasqueAmneziaHybridTunnel struct {
	config  MasqueAmneziaHybridConfig
	masque  *MasqueDatagramTunnel
	packets uint64
	mu      sync.Mutex
}

// NewMasqueAmneziaHybridTunnel creates a synthesized hybrid tunnel
func NewMasqueAmneziaHybridTunnel(cfg MasqueAmneziaHybridConfig) (*MasqueAmneziaHybridTunnel, error) {
	if err := cfg.AmneziaParams.Validate(); err != nil {
		return nil, err
	}
	return &MasqueAmneziaHybridTunnel{
		config: cfg,
		masque: NewMasqueDatagramTunnel(cfg.ContextID),
	}, nil
}

// GenerateHandshakePreamble creates Jc junk packets followed by an initiation frame with H1 header
func (t *MasqueAmneziaHybridTunnel) GenerateHandshakePreamble(initiationPayload []byte) ([][]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	var packets [][]byte

	// 1. Generate Jc junk packets
	for i := 0; i < t.config.AmneziaParams.Jc; i++ {
		span := t.config.AmneziaParams.Jmax - t.config.AmneziaParams.Jmin
		junkLen := t.config.AmneziaParams.Jmin
		if span > 0 {
			var b [1]byte
			_, _ = rand.Read(b[:])
			junkLen += int(b[0]) % span
		}
		junk := make([]byte, junkLen)
		_, _ = rand.Read(junk)
		packets = append(packets, junk)
	}

	// 2. Wrap initiation with H1 header and S1 padding
	var initFrame []byte
	var h1Buf [4]byte
	binary.BigEndian.PutUint32(h1Buf[:], t.config.AmneziaParams.H1)
	initFrame = append(initFrame, h1Buf[:]...)
	initFrame = append(initFrame, initiationPayload...)

	if t.config.AmneziaParams.S1 > 0 {
		pad := make([]byte, t.config.AmneziaParams.S1)
		_, _ = rand.Read(pad)
		initFrame = append(initFrame, pad...)
	}

	// Encapsulate into MASQUE Datagram capsule
	capsule := t.masque.EncodeDatagramCapsule(initFrame)
	packets = append(packets, capsule)
	return packets, nil
}

// EncapsulateDataPacket wraps IP packet with H4 header and MASQUE capsule
func (t *MasqueAmneziaHybridTunnel) EncapsulateDataPacket(ipData []byte) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()

	var framed []byte
	var h4Buf [4]byte
	binary.BigEndian.PutUint32(h4Buf[:], t.config.AmneziaParams.H4)
	framed = append(framed, h4Buf[:]...)
	framed = append(framed, ipData...)

	t.packets++
	return t.masque.EncodeDatagramCapsule(framed)
}

// DecapsulateDataPacket decodes MASQUE datagram, verifies H4 header, and returns inner IP packet
func (t *MasqueAmneziaHybridTunnel) DecapsulateDataPacket(data []byte) ([]byte, error) {
	ctxID, payload, err := t.masque.DecodeDatagramCapsule(data)
	if err != nil {
		return nil, err
	}
	if ctxID != t.config.ContextID {
		return nil, errors.New("context ID mismatch")
	}

	if len(payload) < 4 {
		return nil, errors.New("datagram payload shorter than header")
	}

	msgType := binary.BigEndian.Uint32(payload[0:4])
	if msgType != t.config.AmneziaParams.H4 {
		return nil, errors.New("unexpected message header type")
	}

	return payload[4:], nil
}
