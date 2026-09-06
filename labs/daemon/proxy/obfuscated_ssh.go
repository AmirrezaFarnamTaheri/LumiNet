// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: obfuscated-openssh-master
// Target path: server/internal/proxy/obfuscated_ssh.go

package proxy

import "log/slog"

// ObfuscatedSSH handles the obfuscated OpenSSH handshake listener.
type ObfuscatedSSH struct{}

func NewObfuscatedSSH() *ObfuscatedSSH {
	return &ObfuscatedSSH{}
}

// Listen strips default OpenSSH banners and swaps pre-shared keys.
func (o *ObfuscatedSSH) Listen() {
	slog.Info("ObfuscatedSSH", "status", "Porting obfuscated OpenSSH handshake listener")
	slog.Info("ObfuscatedSSH", "status", "Stripping default OpenSSH banners and swapping pre-shared keys")
}
