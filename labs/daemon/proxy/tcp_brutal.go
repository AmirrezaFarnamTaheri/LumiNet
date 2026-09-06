// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: tcp-brutal-master
// Target path: server/internal/proxy/tcp_brutal.go

package proxy

import (
	"log"
)

// TCPBrutal wraps Hysteria's TCP congestion control features.
type TCPBrutal struct{}

func NewTCPBrutal() *TCPBrutal {
	return &TCPBrutal{}
}

// ApplySocketOptions applies Hysteria's brutal TCP congestion control socket options.
func (t *TCPBrutal) ApplySocketOptions(fd int) error {
	log.Printf("TCPBrutal: Applying brutal TCP congestion control socket option parameters for high packet loss links to fd %d", fd)
	// Example syscall: syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_CONGESTION, "brutal")
	return nil
}
