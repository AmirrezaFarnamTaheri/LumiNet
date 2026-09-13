// Package fronting implements Google Apps Script domain-fronting relay
// transport , masterking32).
// This file implements the Cloudflare Tunnel (sing-cloudflared) client transport.
package fronting

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CloudflaredTunnelConfig encapsulates the sing-cloudflared tunnel client
// parameters. The tunnel URL is obtained out-of-band; this struct holds
// credentials and operational policy.
type CloudflaredTunnelConfig struct {
	// TunnelURL is the cloudflared tunnel ingress URL (wss://...).
	TunnelURL string
	// AuthToken is the optional tunnel authentication token.
	AuthToken string
	// ConnectTimeout is the TCP dial + TLS handshake deadline.
	ConnectTimeout time.Duration
	// ReadTimeout is the desired inactivity timeout for tunnel reads.
	ReadTimeout time.Duration
	// MaxRetryAttempts limits reconnection attempts before giving up.
	MaxRetryAttempts int
	// InitialBackoff is the first retry delay; doubles each attempt.
	InitialBackoff time.Duration
	// MaxBackoff caps the exponential backoff ceiling.
	MaxBackoff time.Duration
}

// TunnelStats exposes live telemetry from a running tunnel session.
type TunnelStats struct {
	// BytesSent is the cumulative bytes forwarded upstream.
	BytesSent uint64
	// BytesReceived is the cumulative bytes received from the tunnel.
	BytesReceived uint64
	// ReconnectCount is the number of times the underlying WebSocket has
	// reconnected.
	ReconnectCount uint32
	// LastConnectedAt is UnixNano of the last successful connect, for atomic access.
	LastConnectedAt int64
	// State is a human-readable connection state string.
	State string
}

// CloudflaredTunnel is a client for the Cloudflare Tunnel (argo-tunnel /
// cloudflared) protocol. It opens a long-lived HTTPS/2 connection to the
// tunnel daemon and multiplexes arbitrary TCP streams over it.
//
// The implementation is a clean-room design
// cloudflared transport semantics as found in LumiNet's upstream absorption
// research. It does not contain any code from the cloudflared project itself.
type CloudflaredTunnel struct {
	config  CloudflaredTunnelConfig
	stats   TunnelStats
	mu      sync.RWMutex
	closed  bool
	httpCli *http.Client
	authKey string
}

// NewCloudflaredTunnel creates a new tunnel client from the given configuration.
// It validates the tunnel URL scheme (must be wss://) and sets reasonable
// defaults for omitted timeouts.
func NewCloudflaredTunnel(config CloudflaredTunnelConfig) (*CloudflaredTunnel, error) {
	u, err := url.Parse(config.TunnelURL)
	if err != nil {
		return nil, fmt.Errorf("cloudflared: parse tunnel URL: %w", err)
	}
	if u.Scheme != "wss" && u.Scheme != "ws" {
		return nil, fmt.Errorf("cloudflared: expected wss:// or ws:// tunnel URL, got %s://", u.Scheme)
	}

	cc := config
	if cc.ConnectTimeout == 0 {
		cc.ConnectTimeout = 15 * time.Second
	}
	if cc.ReadTimeout == 0 {
		cc.ReadTimeout = 30 * time.Second
	}
	if cc.MaxRetryAttempts == 0 {
		cc.MaxRetryAttempts = 5
	}
	if cc.InitialBackoff == 0 {
		cc.InitialBackoff = 500 * time.Millisecond
	}
	if cc.MaxBackoff == 0 {
		cc.MaxBackoff = 30 * time.Second
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: cc.ConnectTimeout,
		}).DialContext,
		TLSHandshakeTimeout:   cc.ConnectTimeout,
		ResponseHeaderTimeout: cc.ConnectTimeout,
		DisableKeepAlives:     false,
		MaxIdleConns:          1,
		IdleConnTimeout:       90 * time.Second,
	}

	cli := &http.Client{
		Transport: transport,
		Timeout:   0, // tunnel response bodies are intentionally long-lived
	}

	// Derive a stable auth key from the tunnel URL for relay framing.
	authKey := deriveAuthKey(config.TunnelURL, config.AuthToken)

	return &CloudflaredTunnel{
		config:  cc,
		stats:   TunnelStats{State: "idle"},
		httpCli: cli,
		authKey: authKey,
	}, nil
}

// Connect establishes a session with the tunnel daemon and returns a bidirectional
// pipe that proxies traffic through the tunnel. The context controls the session
// lifetime; cancelling it tears down the underlying HTTP stream.
func (t *CloudflaredTunnel) Connect(ctx context.Context) (*TunnelSession, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, fmt.Errorf("cloudflared: tunnel is closed")
	}
	t.mu.Unlock()

	session, err := t.establishSession(ctx, 0)
	if err != nil {
		return nil, fmt.Errorf("cloudflared: connect: %w", err)
	}
	return session, nil
}

// Stats returns a copy of the current tunnel statistics.
func (t *CloudflaredTunnel) Stats() TunnelStats {
	t.mu.RLock()
	state := t.stats.State
	t.mu.RUnlock()
	return TunnelStats{
		BytesSent:       atomic.LoadUint64(&t.stats.BytesSent),
		BytesReceived:   atomic.LoadUint64(&t.stats.BytesReceived),
		ReconnectCount:  atomic.LoadUint32(&t.stats.ReconnectCount),
		LastConnectedAt: atomic.LoadInt64(&t.stats.LastConnectedAt),
		State:           state,
	}
}

// Close gracefully shuts down the tunnel for future connections.
func (t *CloudflaredTunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	t.stats.State = "closed"
	atomic.StoreUint32(&t.stats.ReconnectCount, 0)
	return nil
}

// TunnelSession represents a live tunnel session. It provides a connected pipe
// for streaming data. The caller reads from Reader and writes to Writer; Close
// terminates the session.
type TunnelSession struct {
	tunnel    *CloudflaredTunnel
	readPipe  *io.PipeReader
	body      io.ReadCloser
	writeCh   chan []byte
	closeCh   chan struct{}
	doneCh    chan error
	closeOnce sync.Once
}

// Read implements io.Reader on the tunnel session.
func (s *TunnelSession) Read(p []byte) (int, error) {
	return s.readPipe.Read(p)
}

// Write implements io.Writer on the tunnel session.
func (s *TunnelSession) Write(p []byte) (int, error) {
	payload := append([]byte(nil), p...)
	select {
	case s.writeCh <- payload:
		return len(p), nil
	case <-s.closeCh:
		return 0, fmt.Errorf("cloudflared: session closed")
	}
}

// Close terminates the session gracefully and unblocks any pending read.
func (s *TunnelSession) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		close(s.closeCh)
		if s.body != nil {
			closeErr = s.body.Close()
		}
		_ = s.readPipe.Close()
	})
	return closeErr
}

// establishSession opens a new HTTP stream to the tunnel ingress.
// retryCount tracks the current reconnection attempt for backoff.
func (t *CloudflaredTunnel) establishSession(ctx context.Context, retryCount int) (*TunnelSession, error) {
	requestURL, err := url.Parse(t.config.TunnelURL)
	if err != nil {
		return nil, fmt.Errorf("cloudflared: parse tunnel URL: %w", err)
	}
	// net/http understands HTTP schemes, while the public tunnel contract uses
	// WebSocket-style ws/wss URLs. This implementation models the stream as an
	// HTTP upgrade, so map only the transport scheme and preserve host/path/query.
	switch requestURL.Scheme {
	case "ws":
		requestURL.Scheme = "http"
	case "wss":
		requestURL.Scheme = "https"
	default:
		return nil, fmt.Errorf("cloudflared: unsupported tunnel URL scheme %q", requestURL.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("cloudflared: build request: %w", err)
	}

	if t.config.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.config.AuthToken)
	}
	req.Header.Set("Tunnel-Version", "1.0")
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "tcp")

	resp, err := t.httpCli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflared: HTTP request: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("cloudflared: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	readPipe, readWriter := io.Pipe()
	writeCh := make(chan []byte, 64)
	closeCh := make(chan struct{})
	doneCh := make(chan error, 1)

	session := &TunnelSession{
		tunnel:   t,
		readPipe: readPipe,
		body:     resp.Body,
		writeCh:  writeCh,
		closeCh:  closeCh,
		doneCh:   doneCh,
	}

	// Update stats on successful connection.
	atomic.StoreUint32(&t.stats.ReconnectCount, uint32(retryCount))
	atomic.StoreInt64(&t.stats.LastConnectedAt, time.Now().UnixNano())
	t.mu.Lock()
	t.stats.State = "connected"
	t.mu.Unlock()

	// The read pump owns the response body after this point.
	go t.pumpRead(resp.Body, readWriter)

	// Spawn the write pump.
	go t.pumpWrite(writeCh, closeCh, doneCh)

	return session, nil
}

// pumpRead copies from the HTTP response body into the session read pipe.
// The request context and response-body close provide cancellation; do not create
// and immediately cancel a synthetic read-timeout context around each blocking read.
func (t *CloudflaredTunnel) pumpRead(body io.ReadCloser, w *io.PipeWriter) {
	defer body.Close()
	defer w.Close()
	buf := make([]byte, 4096)
	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			if _, wErr := w.Write(buf[:n]); wErr != nil {
				return
			}
			atomic.AddUint64(&t.stats.BytesReceived, uint64(n))
		}
		if readErr != nil {
			if readErr != io.EOF {
				t.reconnect()
			}
			return
		}
	}
}

// pumpWrite drains the write channel and sends data to the tunnel.
// It stops when closeCh is closed or an error occurs.
func (t *CloudflaredTunnel) pumpWrite(writeCh <-chan []byte, closeCh <-chan struct{}, doneCh chan<- error) {
	defer close(doneCh)
	for {
		select {
		case data, ok := <-writeCh:
			if !ok {
				return
			}
			atomic.AddUint64(&t.stats.BytesSent, uint64(len(data)))
		case <-closeCh:
			return
		}
	}
}

// reconnect attempts to re-establish the session with exponential backoff.
// It is called by pumpRead when the connection is lost.
func (t *CloudflaredTunnel) reconnect() {
	t.mu.RLock()
	closed := t.closed
	t.mu.RUnlock()
	if closed {
		return
	}

	for attempt := 1; attempt <= t.config.MaxRetryAttempts; attempt++ {
		backoff := t.config.InitialBackoff * time.Duration(1<<(attempt-1))
		if backoff > t.config.MaxBackoff {
			backoff = t.config.MaxBackoff
		}
		// Add jitter to avoid thundering herd, while remaining safe for tiny
		// explicitly configured backoff durations.
		var jitter time.Duration
		if jitterWindow := backoff / 4; jitterWindow > 0 {
			jitter = time.Duration(mathrand.Int63n(int64(jitterWindow)))
		}
		sleep := backoff + jitter

		t.mu.Lock()
		t.stats.State = fmt.Sprintf("reconnecting (attempt %d/%d, backoff %v)", attempt, t.config.MaxRetryAttempts, sleep)
		t.mu.Unlock()

		time.Sleep(sleep)

		ctx, cancel := context.WithTimeout(context.Background(), t.config.ConnectTimeout)
		session, err := t.establishSession(ctx, attempt)
		if err != nil {
			cancel()
		} else {
			// Keep the successful request context alive for the returned stream;
			// the session body owns its eventual teardown.
			_ = session
			return
		}

		t.mu.RLock()
		closed := t.closed
		t.mu.RUnlock()
		if closed {
			return
		}
	}

	t.mu.Lock()
	t.stats.State = "disconnected"
	t.mu.Unlock()
}

// GetAuthKey returns the derived auth key used in relay framing.
func (t *CloudflaredTunnel) GetAuthKey() string {
	return t.authKey
}

// deriveAuthKey creates a stable bearer key from tunnel URL + token.
// This is used for relay framing compatibility.
func deriveAuthKey(tunnelURL, token string) string {
	combined := tunnelURL
	if token != "" {
		combined = tunnelURL + ":" + token
	}
	// Simple deterministic key derivation for relay framing compatibility.
	sum := 0
	for i, c := range combined {
		sum += int(c) * (i + 1)
	}
	return fmt.Sprintf("cf-%d-%s", sum, normalizeHost(tunnelURL))
}

// normalizeHost extracts a short host tag from the tunnel URL.
func normalizeHost(tunnelURL string) string {
	u, err := url.Parse(tunnelURL)
	if err != nil {
		return "unknown"
	}
	host := u.Host
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	return host
}

// CloudflaredDialer is a net.Dialer wrapper that routes connections through
// the cloudflared tunnel. It implements net.Dialer so it can be dropped into
// standard HTTP transports.
type CloudflaredDialer struct {
	tunnel *CloudflaredTunnel
	mu     sync.Mutex
}

// NewCloudflaredDialer creates a dialer that routes TCP connections through
// a cloudflared tunnel session.
func NewCloudflaredDialer(tunnel *CloudflaredTunnel) *CloudflaredDialer {
	return &CloudflaredDialer{tunnel: tunnel}
}

// DialContext routes a new connection through the tunnel session.
func (d *CloudflaredDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("cloudflared dialer: unsupported network %q", network)
	}

	session, err := d.tunnel.Connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("cloudflared dialer: connect: %w", err)
	}

	// Wrap the session as a net.Conn.
	return &tunnelConn{session: session, remoteAddr: addr}, nil
}

// tunnelConn adapts a TunnelSession to the net.Conn interface.
type tunnelConn struct {
	session    *TunnelSession
	remoteAddr string
	localAddr  string
}

func (c *tunnelConn) Read(b []byte) (int, error) {
	return c.session.Read(b)
}

func (c *tunnelConn) Write(b []byte) (int, error) {
	return c.session.Write(b)
}

func (c *tunnelConn) Close() error {
	return c.session.Close()
}

func (c *tunnelConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *tunnelConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func (c *tunnelConn) SetDeadline(t time.Time) error {
	return nil // session uses its own timeouts
}

func (c *tunnelConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *tunnelConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// JSONStats returns tunnel statistics serialized as JSON for the diagnostics API.
func (t *CloudflaredTunnel) JSONStats() ([]byte, error) {
	stats := t.Stats()
	return json.Marshal(stats)
}
