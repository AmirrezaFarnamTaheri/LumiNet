package transport

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"

	"golang.org/x/crypto/chacha20"
)

// EntropyScrambledTunnel scrambles packets using ChaCha20 keystream and random padding
type EntropyScrambledTunnel struct {
	secretKey  [32]byte
	minPadding int
	maxPadding int
}

// NewEntropyScrambledTunnel creates a new scrambler
func NewEntropyScrambledTunnel(key [32]byte, minPad, maxPad int) *EntropyScrambledTunnel {
	if minPad < 4 {
		minPad = 4
	}
	if maxPad < minPad+8 {
		maxPad = minPad + 8
	}
	return &EntropyScrambledTunnel{
		secretKey:  key,
		minPadding: minPad,
		maxPadding: maxPad,
	}
}

// ScramblePacket formats [2-byte payload len][2-byte pad len][payload][random padding] and masks with ChaCha20
func (t *EntropyScrambledTunnel) ScramblePacket(payload []byte, seed uint64) ([]byte, error) {
	padRange := t.maxPadding - t.minPadding
	padLen := t.minPadding + int(seed%uint64(padRange))

	totalLen := 4 + len(payload) + padLen
	raw := make([]byte, totalLen)

	binary.BigEndian.PutUint16(raw[0:2], uint16(len(payload)))
	binary.BigEndian.PutUint16(raw[2:4], uint16(padLen))
	copy(raw[4:4+len(payload)], payload)

	// Random padding
	if _, err := rand.Read(raw[4+len(payload):]); err != nil {
		return nil, err
	}

	// Mask using ChaCha20
	masked, err := t.applyChaChaMask(raw, seed)
	if err != nil {
		return nil, err
	}
	return masked, nil
}

// DescramblePacket unmasks data using ChaCha20 and extracts payload
func (t *EntropyScrambledTunnel) DescramblePacket(scrambled []byte, seed uint64) ([]byte, error) {
	if len(scrambled) < 4 {
		return nil, errors.New("scrambled packet too short")
	}

	unmasked, err := t.applyChaChaMask(scrambled, seed)
	if err != nil {
		return nil, err
	}

	payloadLen := int(binary.BigEndian.Uint16(unmasked[0:2]))
	padLen := int(binary.BigEndian.Uint16(unmasked[2:4]))

	if len(unmasked) < 4+payloadLen+padLen {
		return nil, errors.New("frame length incomplete")
	}

	res := make([]byte, payloadLen)
	copy(res, unmasked[4:4+payloadLen])
	return res, nil
}

func (t *EntropyScrambledTunnel) applyChaChaMask(data []byte, seed uint64) ([]byte, error) {
	key := t.secretKey
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[0:8], seed)

	stream, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(data))
	stream.XORKeyStream(out, data)
	return out, nil
}

// CalculateShannonEntropy calculates information entropy of byte slice (0.0 to 8.0)
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	entropy := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

var _ cipher.Stream = (*chacha20.Cipher)(nil)
