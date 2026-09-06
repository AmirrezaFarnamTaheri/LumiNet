package proxy

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"time"
)

// OBFS4Config holds parameters for Tor obfs4 pluggable transport emulation.
type OBFS4Config struct {
	NodeID     string `json:"node_id"`
	PublicKey  string `json:"public_key"`
	IATMode    int    `json:"iat_mode"` // Inter-arrival time obfuscation mode
	PaddingMin int    `json:"padding_min"`
	PaddingMax int    `json:"padding_max"`
}

// OBFS4Conn wraps an underlying connection with obfs4 entropy matching and packet padding.
type OBFS4Conn struct {
	net.Conn
	cfg OBFS4Config
	mu  sync.Mutex
}

// NewOBFS4Conn initializes an obfs4 obfuscated connectionwrapper.
func NewOBFS4Conn(conn net.Conn, cfg OBFS4Config) *OBFS4Conn {
	if cfg.PaddingMin <= 0 {
		cfg.PaddingMin = 16
	}
	if cfg.PaddingMax <= cfg.PaddingMin {
		cfg.PaddingMax = 128
	}
	return &OBFS4Conn{
		Conn: conn,
		cfg:  cfg,
	}
}

// Write injects random entropy padding frames prior to sending data payload.
func (c *OBFS4Conn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate random padding length
	padLen := c.cfg.PaddingMin
	if diff := c.cfg.PaddingMax - c.cfg.PaddingMin; diff > 0 {
		var buf [2]byte
		_, _ = rand.Read(buf[:])
		padLen += int(buf[0]) % diff
	}

	padding := make([]byte, padLen)
	_, _ = rand.Read(padding)

	// Send padding frame length and padding
	header := []byte{byte(padLen >> 8), byte(padLen & 0xff)}
	if _, err := c.Conn.Write(header); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(padding); err != nil {
		return 0, err
	}

	return c.Conn.Write(b)
}

// ICMPTunnel implements IP over ICMP Echo Request / Reply payload tunneling (from openvpn-over-icmp).
type ICMPTunnel struct {
	TargetIP string
	Timeout  time.Duration
}

// NewICMPTunnel creates a new ICMP payload tunnel.
func NewICMPTunnel(targetIP string) *ICMPTunnel {
	return &ICMPTunnel{
		TargetIP: targetIP,
		Timeout:  5 * time.Second,
	}
}

// SendPayload sends encapsulated raw data over an ICMP echo packet wrapper.
func (it *ICMPTunnel) SendPayload(ctx context.Context, data []byte) error {
	conn, err := net.DialTimeout("ip4:icmp", it.TargetIP, it.Timeout)
	if err != nil {
		return fmt.Errorf("failed to dial raw ICMP socket: %w", err)
	}
	defer conn.Close()

	// ICMP Echo Request header: Type=8, Code=0, Checksum=0, ID=1, Seq=1
	msg := make([]byte, 8+len(data))
	msg[0] = 8 // Echo Request
	msg[1] = 0 // Code
	msg[4] = 0 // ID
	msg[5] = 1
	msg[6] = 0 // Seq
	msg[7] = 1
	copy(msg[8:], data)

	_, err = conn.Write(msg)
	return err
}
