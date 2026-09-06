// Package tls provides shared TLS types used across the LumiNet server subsystems.
// The Storage interface mirrors certmagic.Storage for pluggable cert backends.
// The canonical implementations live in internal/certs (CertMagicStorage, FileStorage).
package tls

import (
	"context"

	"github.com/maybeknott/luminet/internal/certs"
)

// Storage defines how certificates and metadata are persisted securely.
// This is a forwarding alias to certs.CertMagicStorage, the canonical implementation,
// which matches the certmagic.Storage interface contract.
//
// Use certs.NewFileStorage or certs.NewSQLiteStorage for concrete implementations.
type Storage = certs.CertMagicStorage

// OnDemandConfig configures runtime certificate decision-making for on-demand TLS.
// The DecisionFunc receives a domain and returns nil to allow, or an error to deny
// certificate issuance. This is consumed by AcmeCertManager in internal/proxy.
type OnDemandConfig struct {
	Enabled bool
	// DecisionFunc decides dynamically if a domain is allowed to request a certificate.
	// Return nil to allow, non-nil error to deny. Called once per ALPN handshake.
	DecisionFunc func(ctx context.Context, domain string) error
}
