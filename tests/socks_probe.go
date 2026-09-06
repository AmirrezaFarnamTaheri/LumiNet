// Package integration provides cross-module integration harnesses for
// LumiNet's network-layer subsystems.
//
// Target path: tests/socks_probe.go
//
// Speak RFC 1928 SOCKS5 (no-auth, CONNECT) against a proxy so tests can
// verify reachability and round-trip a payload through the tunneled path.

package integration

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SocksProbe is a reusable SOCKS5 client bound to a single proxy.
// Zero-value Timeout defaults to 10s when not set via WithTimeout.
type SocksProbe struct {
	ProxyAddr string
	Timeout   time.Duration
}

// NewSocksProbe builds a probe targeting `proxyAddr` (host:port) with a
// 10-second default timeout.
func NewSocksProbe(proxyAddr string) *SocksProbe {
	return &SocksProbe{ProxyAddr: proxyAddr, Timeout: 10 * time.Second}
}

// WithTimeout sets the per-op timeout. Chainable.
func (p *SocksProbe) WithTimeout(d time.Duration) *SocksProbe {
	p.Timeout = d
	return p
}

// Connect performs the SOCKS5 handshake (no-auth, CONNECT) to `target`
// (host:port, IPv4:port, [IPv6]:port) and returns the established stream.
// Caller owns Close(). Respects the probe's Timeout when > 0.
func (p *SocksProbe) Connect(ctx context.Context, target string) (net.Conn, error) {
	d := net.Dialer{}
	if p.Timeout > 0 {
		d.Timeout = p.Timeout
	}
	conn, err := d.DialContext(ctx, "tcp", p.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks_probe: dial proxy: %w", err)
	}
	if p.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(p.Timeout))
	}
	if err := p.sock5Auth(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks_probe: auth: %w", err)
	}
	if err := p.sock5Connect(conn, target); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks_probe: connect: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// Ping opens then immediately closes a SOCKS5 connection to `target`.
// Returns nil on success.
func (p *SocksProbe) Ping(ctx context.Context, target string) error {
	conn, err := p.Connect(ctx, target)
	if err != nil {
		return err
	}
	return conn.Close()
}

// RoundTrip opens a SOCKS5 connection, writes `payload`, reads up to 4096
// bytes of response, then closes the stream.
func (p *SocksProbe) RoundTrip(ctx context.Context, target string, payload []byte) ([]byte, error) {
	conn, err := p.Connect(ctx, target)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("socks_probe: write: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("socks_probe: read: %w", err)
	}
	return buf[:n], nil
}

// sock5Auth sends method negotiation: VER=5, NMETHODS=1, METHOD=0x00 (no auth).
// Expects server reply VER=5, METHOD=0x00.
func (p *SocksProbe) sock5Auth(conn net.Conn) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("socks5: bad version %d", resp[0])
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5: method %d not accepted", resp[1])
	}
	return nil
}

// sock5Connect sends a CONNECT request for `target`. Supported targets:
// IPv4:port, [IPv6]:port, hostname:port. ATYP selects v4/v6/domain.
func (p *SocksProbe) sock5Connect(conn net.Conn, target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("socks5: bad port %q: %w", port, err)
	}
	if pn < 0 || pn > 65535 {
		return fmt.Errorf("socks5: port %d out of range", pn)
	}
	var req []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = make([]byte, 0, 10)
			req = append(req, 0x05, 0x01, 0x00, 0x01)
			req = append(req, v4...)
		} else {
			req = make([]byte, 0, 22)
			req = append(req, 0x05, 0x01, 0x00, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("socks5: hostname too long (%d)", len(host))
		}
		req = make([]byte, 0, 7+len(host))
		req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(pn))
	req = append(req, portBytes...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	// Read 4-byte reply header.
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("socks5: reply bad version %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("socks5: connect rejected: REP=%d", hdr[1])
	}
	// Skip BND.ADDR+PORT, length per ATYP in hdr[3].
	var skip int
	switch hdr[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		skip = int(l[0]) + 2
	default:
		return fmt.Errorf("socks5: reply bad ATYP %d", hdr[3])
	}
	skipBuf := make([]byte, skip)
	if _, err := io.ReadFull(conn, skipBuf); err != nil {
		return err
	}
	return nil
}
