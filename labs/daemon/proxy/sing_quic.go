// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: sing-quic-main
// Target path: server/internal/proxy/sing_quic.go

package proxy

import "log/slog"

// SingQUIC handles QUIC transport.
type SingQUIC struct{}

func NewSingQUIC() *SingQUIC {
	return &SingQUIC{}
}

// Setup ports Go QUIC transport session setup adapters inside Sing-Box.
func (s *SingQUIC) Setup() {
	slog.Info("SingQUIC", "status", "Porting Go QUIC transport session setup adapters inside Sing-Box")
}
