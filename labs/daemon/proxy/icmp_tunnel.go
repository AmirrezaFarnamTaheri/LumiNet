// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: lanecove-tunnel-main (peer.c / common.h)
// Target path: server/internal/proxy/icmp_tunnel.go

package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"
)

// RawICMPTunnel implements a secure ICMP encapsulation tunnel with sliding window replay protection (from common.h).
type RawICMPTunnel struct {
	mu           sync.RWMutex
	highestSeq   uint64
	replayWindow [32]uint64
	aesKey       [32]byte
	ivLength     int
	tagLength    int
}

// NewRawICMPTunnel initializes a new RawICMPTunnel instance (from peer.c).
func NewRawICMPTunnel() *RawICMPTunnel {
	t := &RawICMPTunnel{
		ivLength:  12,
		tagLength: 16,
	}
	_, _ = rand.Read(t.aesKey[:])
	return t
}

// CheckReplay implements 2048-bit sliding window replay protection (from common.h check_replay).
func (t *RawICMPTunnel) CheckReplay(seq uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if seq > t.highestSeq {
		diff := seq - t.highestSeq
		if diff >= 32*64 {
			for i := 0; i < 32; i++ {
				t.replayWindow[i] = 0
			}
		} else {
			wordShift := int(diff / 64)
			bitShift := int(diff % 64)
			for i := 31; i >= 0; i-- {
				loSrc := i - wordShift
				hiSrc := loSrc - 1
				var lo, hi uint64
				if loSrc >= 0 {
					lo = t.replayWindow[loSrc]
				}
				if bitShift > 0 && hiSrc >= 0 {
					hi = t.replayWindow[hiSrc]
				}
				if bitShift > 0 {
					t.replayWindow[i] = (lo << bitShift) | (hi >> (64 - bitShift))
				} else {
					t.replayWindow[i] = lo
				}
			}
		}
		t.replayWindow[0] |= 1
		t.highestSeq = seq
		return true // Accepted
	}

	diff := t.highestSeq - seq
	if diff >= 32*64 {
		return false // Too old
	}
	word := int(diff / 64)
	bit := int(diff % 64)
	if (t.replayWindow[word] & (1 << bit)) != 0 {
		return false // Duplicate
	}
	t.replayWindow[word] |= (1 << bit)
	return true
}

// EncryptPacket encrypts the payload using AES-GCM (from common.c encrypt_packet).
func (t *RawICMPTunnel) EncryptPacket(plain []byte) ([]byte, error) {
	t.mu.RLock()
	key := t.aesKey
	t.mu.RUnlock()

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plain, nil)
	// Output: nonce + ciphertext
	out := append(nonce, ciphertext...)
	return out, nil
}

// DecryptPacket decrypts the payload using AES-GCM (from common.c decrypt_packet).
func (t *RawICMPTunnel) DecryptPacket(encrypted []byte) ([]byte, error) {
	if len(encrypted) < 12 {
		return nil, fmt.Errorf("packet too short")
	}

	t.mu.RLock()
	key := t.aesKey
	t.mu.RUnlock()

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := encrypted[:12]
	ciphertext := encrypted[12:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
