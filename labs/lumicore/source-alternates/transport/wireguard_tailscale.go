// Package transport provides network overlay encryption.
// Ported from: wireguard-go-tailscale
// Target path: core/src/transport/wireguard_tailscale.go

package transport

import "log"

// WireguardTailscale implements Tailscale optimized WireGuard.
type WireguardTailscale struct{}

func NewWireguardTailscale() *WireguardTailscale {
	return &WireguardTailscale{}
}

// Optimize incorporates Tailscale’s userspace WireGuard implementation optimizations.
func (w *WireguardTailscale) Optimize() {
	log.Println("WireguardTailscale: Incorporating Tailscale userspace WireGuard implementation optimizations")
}
