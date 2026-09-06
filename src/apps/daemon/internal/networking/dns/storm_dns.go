// Package dns provides DNS resolution and anti-censorship DNS resolver engines.
package dns

import (
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// LowerBase36Codec implements case-insensitive 7-byte block to 11-character Base36 subdomain encoding.
type LowerBase36Codec struct{}

// Encode converts a 7-byte slice into an 11-character base36 string.
func (c *LowerBase36Codec) Encode(src []byte) (string, error) {
	if len(src) != 7 {
		return "", fmt.Errorf("invalid source block size: must be 7 bytes, got %d", len(src))
	}

	val := new(big.Int).SetBytes(src)
	encoded := val.Text(36)

	// Pad with '0' to ensure exactly 11 characters
	if len(encoded) < 11 {
		encoded = strings.Repeat("0", 11-len(encoded)) + encoded
	}

	return encoded, nil
}

// Decode converts an 11-character base36 string back into a 7-byte slice.
func (c *LowerBase36Codec) Decode(src string) ([]byte, error) {
	if len(src) != 11 {
		return nil, fmt.Errorf("invalid encoded string size: must be 11 characters, got %d", len(src))
	}

	val, ok := new(big.Int).SetString(src, 36)
	if !ok {
		return nil, fmt.Errorf("failed to parse base36 string")
	}

	data := val.Bytes()
	if len(data) < 7 {
		padded := make([]byte, 7)
		copy(padded[7-len(data):], data)
		return padded, nil
	}

	return data, nil
}

// StormDNSTunnel coordinates sliding window ARQ transmissions and adaptive RTO updates over DNS.
type StormDNSTunnel struct {
	mu         sync.Mutex
	sndNxt     uint32
	rcvNxt     uint32
	windowSize uint32
	srtt       time.Duration
	rttvar     time.Duration
	rto        time.Duration
	nackList   map[uint32]time.Time
}

// NewStormDNSTunnel creates a new tunnel coordinator.
func NewStormDNSTunnel(windowSize uint32) *StormDNSTunnel {
	return &StormDNSTunnel{
		windowSize: windowSize,
		srtt:       1000 * time.Millisecond,
		rttvar:     500 * time.Millisecond,
		rto:        1500 * time.Millisecond,
		nackList:   make(map[uint32]time.Time),
	}
}

// UpdateRTO applies the Karn/Jacobson adaptive RTO calculation on packet acknowledgment.
func (t *StormDNSTunnel) UpdateRTO(measuredRTT time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Karn/Jacobson Algorithm:
	// RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - measuredRTT|
	// SRTT <- (1 - alpha) * SRTT + alpha * measuredRTT
	// RTO <- SRTT + max(G, K * RTTVAR)
	const alpha = 0.125
	const beta = 0.25

	if t.srtt == 0 {
		t.srtt = measuredRTT
		t.rttvar = measuredRTT / 2
	} else {
		diff := t.srtt - measuredRTT
		if diff < 0 {
			diff = -diff
		}
		// Apply updates
		t.rttvar = time.Duration((1.0-beta)*float64(t.rttvar) + beta*float64(diff))
		t.srtt = time.Duration((1.0-alpha)*float64(t.srtt) + alpha*float64(measuredRTT))
	}

	t.rto = t.srtt + 4*t.rttvar
	if t.rto < 500*time.Millisecond {
		t.rto = 500 * time.Millisecond
	} else if t.rto > 30*time.Second {
		t.rto = 30 * time.Second
	}
}

// GetStatus returns the current protocol states.
func (t *StormDNSTunnel) GetStatus() (uint32, uint32, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sndNxt, t.rcvNxt, t.rto
}
