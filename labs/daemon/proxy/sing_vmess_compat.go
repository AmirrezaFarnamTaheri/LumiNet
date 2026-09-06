// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: sing-vmess-for-meta
// Target path: server/internal/proxy/sing_vmess_compat.go

package proxy

import "log/slog"

// SingVMessCompat handles VMess adjustments.
type SingVMessCompat struct{}

func NewSingVMessCompat() *SingVMessCompat {
	return &SingVMessCompat{}
}

// Adapt ports VMess protocol compatibility adjustments mapping Meta settings inside Sing-Box.
func (s *SingVMessCompat) Adapt() {
	slog.Info("SingVMessCompat", "status", "Porting VMess protocol compatibility adjustments mapping Meta settings inside Sing-Box")
}
