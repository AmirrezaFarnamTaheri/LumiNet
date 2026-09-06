// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: BegzarApp
// Target path: server/internal/proxy/begzar.go

package proxy

import (
	"log/slog"
)

// BegzarAppWrapper wraps BegzarTunnel for Flutter bindings.
type BegzarAppWrapper struct {
	Tunnel *BegzarTunnel
}

// NewBegzarAppWrapper initializes the wrapper.
func NewBegzarAppWrapper() *BegzarAppWrapper {
	return &BegzarAppWrapper{
		Tunnel: NewBegzarTunnel(),
	}
}

// StartTunnel triggers the internal segment SDK tunnel.
func (w *BegzarAppWrapper) StartTunnel() error {
	slog.Info("BegzarAppWrapper", "status", "Starting tunnel from wrapper context")
	return w.Tunnel.StartSegmentSDKTunnel()
}
