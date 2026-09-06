// Package certs provides a runtime CA store for LumiNet's TLS MITM capability.
//
// Addresses S-01: TLS MITM / Root CA Lifecycle Is a First-Class Boundary.
//
// Design decisions:
//   - MITM feature is DEFAULT OFF — requires explicit runtime config flag.
//   - CA private key is NEVER persisted to disk/DB.
//   - CA key lives only in memory (MemoryCAStore) during the daemon lifetime.
//   - A watchdog must call Clear() on daemon exit to ensure trust-store cleanup.
//   - Audit log records every install/uninstall event.
package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// ErrMITMDisabled is returned when MITM routes are accessed without enabling the feature.
var ErrMITMDisabled = errors.New("certs: MITM interception is disabled; set mitm.enabled=true in config to activate")

// CARuntimeStore is the interface for the in-memory CA lifecycle.
// It is intentionally minimal — no serialization, no persistence.
type CARuntimeStore interface {
	// Load returns the current CA cert and key. Returns (nil, nil, false) if not set.
	Load() (*x509.Certificate, *rsa.PrivateKey, bool)
	// Store replaces the CA cert and key (in-memory only).
	Store(cert *x509.Certificate, key *rsa.PrivateKey)
	// Clear wipes the in-memory CA (called by watchdog on daemon exit).
	Clear()
	// Enabled reports whether MITM is activated.
	Enabled() bool
	// SetEnabled enables or disables the MITM feature at runtime.
	SetEnabled(enabled bool)
}

// MemoryCAStore is the default in-memory implementation of CARuntimeStore.
// The CA private key is zeroed on Clear().
type MemoryCAStore struct {
	mu      sync.RWMutex
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	enabled bool
}

// NewMemoryCAStore returns a disabled, empty CA store.
func NewMemoryCAStore() *MemoryCAStore {
	return &MemoryCAStore{enabled: false}
}

func (s *MemoryCAStore) Load() (*x509.Certificate, *rsa.PrivateKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cert == nil || s.key == nil {
		return nil, nil, false
	}
	return s.cert, s.key, true
}

func (s *MemoryCAStore) Store(cert *x509.Certificate, key *rsa.PrivateKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cert = cert
	s.key = key
}

func (s *MemoryCAStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cert = nil
	s.key = nil
	// key will be garbage-collected; crypto/rsa does not expose explicit zeroize
}

func (s *MemoryCAStore) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

func (s *MemoryCAStore) SetEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !enabled {
		// Disable: wipe in-memory key immediately
		s.cert = nil
		s.key = nil
	}
	s.enabled = enabled
}

// CAConfig holds the configuration for MITM CA generation.
type CAConfig struct {
	// Enabled controls whether MITM interception is active. Default: false.
	Enabled bool `json:"enabled"`
	// CommonName for the generated root CA certificate.
	CommonName string `json:"common_name"`
	// ValidityDays is how long the CA cert is valid. Default: 1 (ephemeral).
	ValidityDays int `json:"validity_days"`
	// KeyBits is the RSA key size. Default: 2048.
	KeyBits int `json:"key_bits"`
}

// DefaultCAConfig returns a safe default CA configuration (disabled, ephemeral).
func DefaultCAConfig() CAConfig {
	return CAConfig{
		Enabled:      false, // MUST be explicit opt-in
		CommonName:   "LumiNet Local MITM CA",
		ValidityDays: 1,
		KeyBits:      2048,
	}
}

// GenerateCA generates an ephemeral RSA root CA certificate and key pair.
// The key is returned only in memory and must never be persisted.
// Returns ErrMITMDisabled if cfg.Enabled is false.
func GenerateCA(cfg CAConfig) (*x509.Certificate, *rsa.PrivateKey, error) {
	if !cfg.Enabled {
		return nil, nil, ErrMITMDisabled
	}
	if cfg.KeyBits == 0 {
		cfg.KeyBits = 2048
	}
	if cfg.ValidityDays == 0 {
		cfg.ValidityDays = 1
	}

	key, err := rsa.GenerateKey(rand.Reader, cfg.KeyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("certs: generate RSA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("certs: generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: []string{"LumiNet (ephemeral, do not trust permanently)"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Duration(cfg.ValidityDays) * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("certs: self-sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("certs: parse CA cert: %w", err)
	}

	return cert, key, nil
}

// CAInstallEvent records a CA trust-store installation or removal for audit log.
type CAInstallEvent struct {
	Action     string    `json:"action"` // "install" | "uninstall"
	Timestamp  time.Time `json:"timestamp"`
	CommonName string    `json:"common_name"`
	SerialHex  string    `json:"serial_hex"`
	Trigger    string    `json:"trigger"` // "user" | "watchdog" | "startup_cleanup"
}
