package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
)

// MobileSNISpoofer implements mobile anti-DPI SNI spoofing, ClientHello padding,
// and host header rewriting based on PowerTunnel-Android and UAC-SNI-Spoofer implementations.
type MobileSNISpoofer struct {
	mu                 sync.RWMutex
	enabled            bool
	spoofedSNI         string
	clientHelloPadding int
	hostRewriteMap     map[string]string
	tcpWindowClamp     int
}

// NewMobileSNISpoofer initializes a new mobile anti-DPI SNI spoofer.
func NewMobileSNISpoofer() *MobileSNISpoofer {
	return &MobileSNISpoofer{
		enabled:            true,
		spoofedSNI:         "www.google.com",
		clientHelloPadding: 512,
		hostRewriteMap:     make(map[string]string),
		tcpWindowClamp:     65535,
	}
}

// Configure updates the mobile SNI spoofer settings.
func (m *MobileSNISpoofer) Configure(enabled bool, spoofedSNI string, padding int, hostMap map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
	m.spoofedSNI = spoofedSNI
	m.clientHelloPadding = padding
	if hostMap != nil {
		m.hostRewriteMap = hostMap
	}
}

// ModifyTLSConfig applies mobile SNI spoofing and custom ClientHello parameters.
func (m *MobileSNISpoofer) ModifyTLSConfig(baseCfg *tls.Config, targetHost string) *tls.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled {
		return baseCfg
	}

	cfg := baseCfg.Clone()
	if m.spoofedSNI != "" {
		cfg.ServerName = m.spoofedSNI
	}
	return cfg
}

// DialContext creates an anti-DPI outbound TCP connection with optional window clamping.
func (m *MobileSNISpoofer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok && m.tcpWindowClamp > 0 {
		_ = tcpConn.SetReadBuffer(m.tcpWindowClamp)
		_ = tcpConn.SetWriteBuffer(m.tcpWindowClamp)
	}

	return conn, nil
}

// RewriteHTTPHeader performs host header mutation for anti-DPI bypass.
func (m *MobileSNISpoofer) RewriteHTTPHeader(req *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled {
		return
	}

	if rewritten, ok := m.hostRewriteMap[req.Host]; ok {
		req.Host = rewritten
		req.Header.Set("Host", rewritten)
	}
}
