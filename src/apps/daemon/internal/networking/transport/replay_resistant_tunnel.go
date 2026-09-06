package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

type ReplayResistantConfig struct {
	PSK              []byte
	MaxSkewSecs      int64
	MaxTrackedNonces int
}

func DefaultReplayResistantConfig() ReplayResistantConfig {
	return ReplayResistantConfig{
		PSK:              []byte("luminet-default-replay-psk-2026"),
		MaxSkewSecs:      60,
		MaxTrackedNonces: 4096,
	}
}

type ReplayResistantTunnelSession struct {
	config        ReplayResistantConfig
	sessionKey    []byte
	lastRemoteSeq uint64
	seenNonces    map[[12]byte]struct{}
}

func NewReplayResistantTunnelSession(config ReplayResistantConfig, clientRandom, serverRandom []byte) *ReplayResistantTunnelSession {
	hk := hkdf.New(sha256.New, config.PSK, clientRandom, serverRandom)
	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(hk, sessionKey); err != nil {
		// Fallback deterministic expand
		h := sha256.Sum256(append(config.PSK, append(clientRandom, serverRandom...)...))
		copy(sessionKey, h[:])
	}

	return &ReplayResistantTunnelSession{
		config:        config,
		sessionKey:    sessionKey,
		lastRemoteSeq: 0,
		seenNonces:    make(map[[12]byte]struct{}),
	}
}

func (s *ReplayResistantTunnelSession) SealPacket(sequence uint64, timestamp int64, payload []byte) []byte {
	packet := make([]byte, 8+8+12+len(payload))
	binary.BigEndian.PutUint64(packet[0:8], sequence)
	binary.BigEndian.PutUint64(packet[8:16], uint64(timestamp))

	var nonce [12]byte
	seqBytes := packet[0:8]
	tsBytes := packet[8:16]
	for i := 0; i < 8; i++ {
		nonce[i] = seqBytes[i] ^ s.sessionKey[i]
	}
	for i := 0; i < 4; i++ {
		nonce[8+i] = tsBytes[i] ^ s.sessionKey[8+i]
	}
	copy(packet[16:28], nonce[:])

	for i, b := range payload {
		k := s.sessionKey[(i+int(nonce[i%12]))%len(s.sessionKey)]
		packet[28+i] = b ^ k
	}

	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write(packet)
	tag := mac.Sum(nil)
	packet = append(packet, tag[:16]...)

	return packet
}

func (s *ReplayResistantTunnelSession) OpenPacket(packet []byte, currentTime int64) (uint64, int64, []byte, error) {
	if len(packet) < 8+8+12+16 {
		return 0, 0, nil, errors.New("packet smaller than replay envelope minimum")
	}

	sequence := binary.BigEndian.Uint64(packet[0:8])
	timestamp := int64(binary.BigEndian.Uint64(packet[8:16]))

	diff := currentTime - timestamp
	if diff < 0 {
		diff = -diff
	}
	if diff > s.config.MaxSkewSecs {
		return 0, 0, nil, fmt.Errorf("timestamp skew too large: %d s", diff)
	}

	var nonce [12]byte
	copy(nonce[:], packet[16:28])

	if _, exists := s.seenNonces[nonce]; exists {
		return 0, 0, nil, errors.New("replay detected: duplicate nonce")
	}

	bodyEnd := len(packet) - 16
	providedTag := packet[bodyEnd:]

	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write(packet[:bodyEnd])
	expectedTag := mac.Sum(nil)[:16]
	if !hmac.Equal(providedTag, expectedTag) {
		return 0, 0, nil, errors.New("integrity verification failed")
	}

	if sequence <= s.lastRemoteSeq && s.lastRemoteSeq > 0 {
		return 0, 0, nil, fmt.Errorf("out of order sequence: got %d, last %d", sequence, s.lastRemoteSeq)
	}

	encPayload := packet[28:bodyEnd]
	decrypted := make([]byte, len(encPayload))
	for i, b := range encPayload {
		k := s.sessionKey[(i+int(nonce[i%12]))%len(s.sessionKey)]
		decrypted[i] = b ^ k
	}

	if len(s.seenNonces) >= s.config.MaxTrackedNonces {
		s.seenNonces = make(map[[12]byte]struct{})
	}
	s.seenNonces[nonce] = struct{}{}
	s.lastRemoteSeq = sequence

	return sequence, timestamp, decrypted, nil
}
