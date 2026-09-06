package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/maybeknott/luminet/internal/networking/geoip"
	"github.com/maybeknott/luminet/internal/protocols/tlsfragment"
)

// AdaptiveDialer configures the adaptive DPI evasion strategy.
type AdaptiveDialer struct {
	ProxyHost  string
	ProxyPort  uint16
	UTLSConfig tlsfragment.UTLSFragmentConfig
	Timeout    time.Duration
}

// Dial intelligently attempts connection, falling back to stronger evasion if blocked.
func (d *AdaptiveDialer) Dial(ctx context.Context) (net.Conn, error) {
	// If target is a private LAN IP (excluding loopback for testing), bypass uTLS fragmentation and kernel-level raw bypass.
	if geoip.IsLocalOrLanIP(d.ProxyHost) && d.ProxyHost != "127.0.0.1" && d.ProxyHost != "::1" {
		targetAddr := fmt.Sprintf("%s:%d", d.ProxyHost, d.ProxyPort)
		dialer := &net.Dialer{Timeout: d.Timeout}
		return dialer.DialContext(ctx, "tcp", targetAddr)
	}

	// 1. Attempt User-Space uTLS Fragmentation first
	targetAddr := fmt.Sprintf("%s:%d", d.ProxyHost, d.ProxyPort)
	dialer := &net.Dialer{Timeout: d.Timeout}

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err == nil {
		// Wrap with uTLS fragmentation
		fragConn := tlsfragment.WrapUTLSFragmentConn(conn, d.UTLSConfig)
		// We could do a quick health-check write/read here to see if the censor RSTs it.
		// If it gets RST immediately upon writing the fragmented ClientHello, it would fail.
		// For now, we assume if dial succeeds, we return the wrapped connection.
		// If the write fails later, the auto-reconnect layer will trigger a re-dial.
		return fragConn, nil
	}

	// 2. If standard dial with fragmentation fails (e.g. SNI block drops SYN/ACK),
	// escalate to Kernel-Level WinDivert packet injection (out-of-window SYN/ClientHello).

	rawConn, err := DialRawBypass(ctx, d.ProxyHost, d.ProxyPort)
	if err != nil {
		return nil, fmt.Errorf("adaptive dial failed all evasion stages: %w", err)
	}

	return rawConn, nil
}
