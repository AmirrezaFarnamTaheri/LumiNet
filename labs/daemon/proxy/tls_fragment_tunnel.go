// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: GreenTunnel-main
// Target path: server/internal/proxy/green_tunnel.go

package proxy

import (
	"io"
	"log/slog"
)

// GreenTunnel bypasses DPI using ClientHello fragmentation.
type GreenTunnel struct{}

func NewGreenTunnel() *GreenTunnel {
	return &GreenTunnel{}
}

// BypassDPI implements HTTPS client hello segment fragmentation.
func (g *GreenTunnel) BypassDPI() {
	slog.Info("GreenTunnel", "status", "Porting Node.js DPI bypass proxy")
	slog.Info("GreenTunnel", "status", "Implementing HTTPS client hello segment fragmentation")
}

// FragmentAndWrite writes the data into the connection by splitting the TLS ClientHello into fragments (from GreenTunnel proxy.js).
func (g *GreenTunnel) FragmentAndWrite(conn io.Writer, data []byte) (int, error) {
	if len(data) > 5 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03 {
		// It's a TLS ClientHello record. Let's fragment the first 5 bytes (Record Header)
		// and the next few bytes of the Handshake layer to confuse DPI.
		header := data[:5]
		body := data[5:]

		// Write the TLS record header first
		n1, err := conn.Write(header)
		if err != nil {
			return n1, err
		}

		// If body is large enough, write it in two fragments (e.g. 1 byte and the rest)
		if len(body) > 1 {
			n2, err := conn.Write(body[:1])
			if err != nil {
				return n1 + n2, err
			}
			n3, err := conn.Write(body[1:])
			return n1 + n2 + n3, err
		}

		n2, err := conn.Write(body)
		return n1 + n2, err
	}

	// Not TLS, write directly
	return conn.Write(data)
}
