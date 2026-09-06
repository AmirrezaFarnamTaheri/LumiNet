package proxyconfig

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

// CipherSuite identifies AEAD ciphers for Hybrid Shadow V2
type CipherSuite string

const (
	CipherAes256Gcm    CipherSuite = "AEAD_AES_256_GCM"
	CipherChacha20Poly CipherSuite = "AEAD_CHACHA20_POLY1305"
)

// HybridShadowConfig holds configuration for Shadowsocks V2 hybrid transport
type HybridShadowConfig struct {
	Cipher          CipherSuite
	PreSharedKey    []byte
	ReplayWindowSec int
	SaltLength      int
	EnablePadding   bool
}

// SessionSaltRecord tracks used salts to prevent replay attacks
type SessionSaltRecord struct {
	Timestamp time.Time
}

// HybridShadowV2Transport manages Shadowsocks 2022 / V2 hybrid stream session state
type HybridShadowV2Transport struct {
	config      HybridShadowConfig
	saltHistory map[string]SessionSaltRecord
	mu          sync.RWMutex
}

// NewHybridShadowV2Transport creates a new transport instance
func NewHybridShadowV2Transport(config HybridShadowConfig) (*HybridShadowV2Transport, error) {
	if len(config.PreSharedKey) < 16 {
		return nil, errors.New("pre-shared key must be at least 16 bytes")
	}
	if config.SaltLength <= 0 {
		config.SaltLength = 32
	}
	if config.ReplayWindowSec <= 0 {
		config.ReplayWindowSec = 120
	}
	return &HybridShadowV2Transport{
		config:      config,
		saltHistory: make(map[string]SessionSaltRecord),
	}, nil
}

// GenerateSalt creates an ephemeral cryptographic salt
func (t *HybridShadowV2Transport) GenerateSalt() ([]byte, error) {
	salt := make([]byte, t.config.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// DeriveSubkey derives session key from PSK and salt via HMAC-SHA256
func (t *HybridShadowV2Transport) DeriveSubkey(salt []byte) []byte {
	mac := hmac.New(sha256.New, t.config.PreSharedKey)
	mac.Write(salt)
	mac.Write([]byte("hybrid-shadow-v2-subkey"))
	return mac.Sum(nil)
}

// RegisterSalt validates that salt is fresh and not replayed
func (t *HybridShadowV2Transport) RegisterSalt(salt []byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	// Purge stale salts
	cutoff := now.Add(-time.Duration(t.config.ReplayWindowSec) * time.Second)
	for k, v := range t.saltHistory {
		if v.Timestamp.Before(cutoff) {
			delete(t.saltHistory, k)
		}
	}

	saltKey := string(salt)
	if _, exists := t.saltHistory[saltKey]; exists {
		return false // replay detected
	}

	t.saltHistory[saltKey] = SessionSaltRecord{Timestamp: now}
	return true
}

// FramePayload encapsulates raw payload with salt and optional random padding
func (t *HybridShadowV2Transport) FramePayload(salt []byte, payload []byte) []byte {
	var framed []byte
	framed = append(framed, byte(len(salt)))
	framed = append(framed, salt...)

	// Length prefix (2 bytes big endian)
	pLen := len(payload)
	framed = append(framed, byte(pLen>>8), byte(pLen&0xFF))
	framed = append(framed, payload...)
	return framed
}

// UnframePayload extracts salt and payload from framed data
func (t *HybridShadowV2Transport) UnframePayload(data []byte) ([]byte, []byte, error) {
	if len(data) < 3 {
		return nil, nil, errors.New("data too short for hybrid frame")
	}
	saltLen := int(data[0])
	if len(data) < 1+saltLen+2 {
		return nil, nil, errors.New("truncated frame header")
	}
	salt := data[1 : 1+saltLen]
	pLen := (int(data[1+saltLen]) << 8) | int(data[2+saltLen])
	start := 3 + saltLen
	if len(data) < start+pLen {
		return nil, nil, errors.New("payload length mismatch")
	}
	payload := data[start : start+pLen]
	return salt, payload, nil
}
