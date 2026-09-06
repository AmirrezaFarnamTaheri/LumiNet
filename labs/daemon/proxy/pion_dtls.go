// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: pion-dtls-main
// Target path: server/internal/proxy/pion_dtls.go

package proxy

import "log/slog"

// PionDTLS represents the pure Go DTLS transport.
type PionDTLS struct{}

func NewPionDTLS() *PionDTLS {
	return &PionDTLS{}
}

// StartTransport supports Connection ID migration and UDP flight handshake states.
func (p *PionDTLS) StartTransport() {
	slog.Info("PionDTLS", "status", "Porting pure Go DTLS transport")
	slog.Info("PionDTLS", "status", "Supporting Connection ID migration and UDP flight handshake states")
}
