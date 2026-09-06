package proxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/maybeknott/luminet/internal/integrations/relayclient"
	utls "github.com/refraction-networking/utls"
)

// WsTunnelClient represents the WebSocket / TLS proxy connection wrapper.
type WsTunnelClient struct {
	Endpoint          string
	Headers           map[string]string
	TLSName           string
	UseUTLS           bool
	Fingerprint       string // e.g. "chrome", "firefox", "random", "random_no_alpn"
	ExtraPadding      bool
	TunnelType        int          // 1 = WSTunnel (WebSocket), 2 = Stunnel (TCP/TLS)
	SocketProtect     func(fd int) // Android socket protection callback
	PinnedFingerprint string
	version           int
	logLevel          string
	timeout           time.Duration
	maxRetries        int
	activeConns       int32
}

// NewWsTunnelClient creates a new WsTunnelClient.
func NewWsTunnelClient(endpoint string) *WsTunnelClient {
	return &WsTunnelClient{
		Endpoint:   endpoint,
		Headers:    make(map[string]string),
		TunnelType: 1, // Default to WSTunnel
	}
}

// EstablishTunnel dials the WebSocket/TLS endpoint and upgrades/wraps the connection.
func (c *WsTunnelClient) EstablishTunnel(ctx context.Context) (net.Conn, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}

	if c.TunnelType == 2 { // Stunnel (raw TCP/TLS)
		conn, err := dialTLSWithUTLS(ctx, "tcp", u.Host, u, c.Fingerprint, c.ExtraPadding, c.TLSName, c.PinnedFingerprint, c.SocketProtect)
		if err != nil {
			return nil, fmt.Errorf("stunnel connection failed: %w", err)
		}
		return conn, nil
	}

	dialer := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	if c.UseUTLS && (u.Scheme == "wss" || u.Scheme == "https") {
		dialer.NetDialTLSContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			return dialTLSWithUTLS(dialCtx, network, addr, u, c.Fingerprint, c.ExtraPadding, c.TLSName, c.PinnedFingerprint, c.SocketProtect)
		}
	} else {
		// Use standard TCP dialer with protect callback if provided
		dialer.NetDialContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{}
			if c.SocketProtect != nil {
				d.Control = func(network, address string, rc syscall.RawConn) error {
					return rc.Control(func(fd uintptr) {
						c.SocketProtect(int(fd))
					})
				}
			}
			return d.DialContext(dialCtx, network, addr)
		}
	}

	header := http.Header{}
	for k, v := range c.Headers {
		header.Set(k, v)
	}

	// Enforce custom browser headers for evasion audit if not specified
	if header.Get("User-Agent") == "" {
		header.Set("User-Agent", getRandomUserAgent())
	}
	if header.Get("Accept") == "" {
		header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	}
	if header.Get("Accept-Language") == "" {
		header.Set("Accept-Language", "en-US,en;q=0.5")
	}

	wsConn, _, err := dialer.DialContext(ctx, c.Endpoint, header)
	if err != nil {
		return nil, fmt.Errorf("wstunnel connection failed: %w", err)
	}

	var relayConn *relayclient.WebSocketConn = relayclient.NewWebSocketConn(wsConn)
	return relayConn, nil
}

func dialTLSWithUTLS(ctx context.Context, network, addr string, u *url.URL, fingerprint string, extraPadding bool, tlsName string, pinnedFingerprint string, protect func(fd int)) (net.Conn, error) {
	dialer := &net.Dialer{}
	if protect != nil {
		dialer.Control = func(network, address string, rc syscall.RawConn) error {
			return rc.Control(func(fd uintptr) {
				protect(int(fd))
			})
		}
	}
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	serverName := tlsName
	if serverName == "" {
		serverName = u.Hostname()
	}

	// A configured certificate pin is an explicit trust root and is verified
	// immediately after the handshake. Without a pin, use normal PKI
	// verification; live tunnel traffic must never default to trust-any-cert.
	uconn := utls.UClient(tcpConn, &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: strings.TrimSpace(pinnedFingerprint) != "", // pin verification below replaces PKI only when explicitly configured
	}, utls.HelloCustom)

	var utlsID utls.ClientHelloID
	switch strings.ToLower(fingerprint) {
	case "chrome":
		utlsID = utls.HelloChrome_Auto
	case "firefox":
		utlsID = utls.HelloFirefox_Auto
	case "random_no_alpn":
		utlsID = utls.HelloRandomizedNoALPN
	default:
		utlsID = utls.HelloRandomizedALPN
	}

	spec, err := utls.UTLSIdToSpec(utlsID)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to retrieve utls spec: %w", err)
	}

	if extraPadding {
		hasPadding := false
		padLenVal, err := rand.Int(rand.Reader, big.NewInt(10000))
		padLen := 2000
		if err == nil {
			padLen += int(padLenVal.Int64())
		}
		for _, ext := range spec.Extensions {
			if pExt, ok := ext.(*utls.UtlsPaddingExtension); ok {
				hasPadding = true
				pExt.PaddingLen = padLen
				pExt.WillPad = true
				pExt.GetPaddingLen = nil
				break
			}
		}
		if !hasPadding {
			spec.Extensions = append(spec.Extensions, &utls.UtlsPaddingExtension{
				PaddingLen: padLen,
				WillPad:    true,
			})
		}
	}

	err = uconn.ApplyPreset(&spec)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to apply utls spec preset: %w", err)
	}

	err = uconn.HandshakeContext(ctx)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("utls handshake failed: %w", err)
	}

	if pinnedFingerprint != "" {
		state := uconn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			uconn.Close()
			return nil, fmt.Errorf("no peer certificates presented")
		}
		leaf := state.PeerCertificates[0]
		h := sha256.Sum256(leaf.Raw)
		fingerprintHex := hex.EncodeToString(h[:])
		if !strings.EqualFold(fingerprintHex, pinnedFingerprint) {
			uconn.Close()
			return nil, fmt.Errorf("pinned certificate fingerprint mismatch: got %s, want %s", fingerprintHex, pinnedFingerprint)
		}
	}

	return uconn, nil
}

func getRandomUserAgent() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(uas))))
	if err != nil {
		return uas[0]
	}
	return uas[n.Int64()]
}

// StunnelBiDirection transfers data between local net.Conn and remote *utls.UConn bidirectionally.
type StunnelBiDirection struct {
	localConn  net.Conn
	remoteConn *utls.UConn
	mtu        int
}

// NewStunnelBiDirection creates a new StunnelBiDirection.
func NewStunnelBiDirection(localConn net.Conn, remoteConn *utls.UConn, mtu int) *StunnelBiDirection {
	return &StunnelBiDirection{
		localConn:  localConn,
		remoteConn: remoteConn,
		mtu:        mtu,
	}
}

// Run starts the bidirectional copy loops.
func (s *StunnelBiDirection) Run() error {
	go s.sendTCPToStunnel()
	s.sendStunnelToTCP()
	return nil
}

func (s *StunnelBiDirection) sendTCPToStunnel() {
	defer s.close()
	data := make([]byte, s.mtu)
	for {
		readSize, err := s.localConn.Read(data)
		if err != nil {
			return
		}
		_, err = s.remoteConn.Write(data[:readSize])
		if err != nil {
			return
		}
	}
}

func (s *StunnelBiDirection) sendStunnelToTCP() {
	defer s.close()
	data := make([]byte, s.mtu)
	for {
		readSize, err := s.remoteConn.Read(data)
		if err != nil {
			break
		}
		_, err = s.localConn.Write(data[:readSize])
		if err != nil {
			return
		}
	}
}

func (s *StunnelBiDirection) close() {
	_ = s.remoteConn.Close()
	_ = s.localConn.Close()
}

// SetFingerprint overrides uTLS fingerprint string.
func (c *WsTunnelClient) SetFingerprint(fp string) {
	c.Fingerprint = fp
}

// GetFingerprint retrieves uTLS fingerprint string.
func (c *WsTunnelClient) GetFingerprint() string {
	return c.Fingerprint
}

// SetExtraPadding overrides padding configuration.
func (c *WsTunnelClient) SetExtraPadding(enabled bool) {
	c.ExtraPadding = enabled
}

// GetExtraPadding retrieves padding configuration.
func (c *WsTunnelClient) GetExtraPadding() bool {
	return c.ExtraPadding
}

// SetPinnedFingerprint overrides pinned leaf certificate hash.
func (c *WsTunnelClient) SetPinnedFingerprint(pf string) {
	c.PinnedFingerprint = pf
}

// GetPinnedFingerprint retrieves pinned leaf certificate hash.
func (c *WsTunnelClient) GetPinnedFingerprint() string {
	return c.PinnedFingerprint
}

// SetTLSName overrides destination server hostname.
func (c *WsTunnelClient) SetTLSName(name string) {
	c.TLSName = name
}

// GetTLSName retrieves destination server hostname.
func (c *WsTunnelClient) GetTLSName() string {
	return c.TLSName
}

// SetEndpoint overrides target WebSocket / TLS proxy endpoint URL.
func (c *WsTunnelClient) SetEndpoint(endpoint string) {
	c.Endpoint = endpoint
}

// GetEndpoint retrieves target WebSocket / TLS proxy endpoint URL.
func (c *WsTunnelClient) GetEndpoint() string {
	return c.Endpoint
}

// SetUseUTLS overrides uTLS client hello spoofing framework status.
func (c *WsTunnelClient) SetUseUTLS(use bool) {
	c.UseUTLS = use
}

// GetUseUTLS retrieves uTLS client hello spoofing framework status.
func (c *WsTunnelClient) GetUseUTLS() bool {
	return c.UseUTLS
}

// SetTunnelType overrides proxy transport tunnel mode selection index.
func (c *WsTunnelClient) SetTunnelType(t int) {
	c.TunnelType = t
}

// GetTunnelType retrieves proxy transport tunnel mode selection index.
func (c *WsTunnelClient) GetTunnelType() int {
	return c.TunnelType
}

// SetHeaders overrides target HTTP request headers map.
func (c *WsTunnelClient) SetHeaders(headers map[string]string) {
	copied := make(map[string]string)
	for k, v := range headers {
		copied[k] = v
	}
	c.Headers = copied
}

// GetHeaders retrieves target HTTP request headers map.
func (c *WsTunnelClient) GetHeaders() map[string]string {
	copied := make(map[string]string)
	for k, v := range c.Headers {
		copied[k] = v
	}
	return copied
}

// AddHeader registers custom HTTP header parameter mapping.
func (c *WsTunnelClient) AddHeader(key, val string) {
	c.Headers[key] = val
}

// GetHeader retrieves custom HTTP header parameter value.
func (c *WsTunnelClient) GetHeader(key string) (string, bool) {
	val, exists := c.Headers[key]
	return val, exists
}

// RemoveHeader deletes custom HTTP header parameter mapping.
func (c *WsTunnelClient) RemoveHeader(key string) bool {
	_, exists := c.Headers[key]
	if exists {
		delete(c.Headers, key)
	}
	return exists
}

// ClearHeaders flushes custom HTTP headers registry map.
func (c *WsTunnelClient) ClearHeaders() {
	c.Headers = make(map[string]string)
}

// GetHeadersCount retrieves count of active custom headers.
func (c *WsTunnelClient) GetHeadersCount() int {
	return len(c.Headers)
}

// SetVersion overrides configuration schema version.
func (c *WsTunnelClient) SetVersion(v int) {
	c.version = v
}

// GetVersion retrieves configuration schema version.
func (c *WsTunnelClient) GetVersion() int {
	return c.version
}

// SetLogLevel overrides diagnostic log levels filter tag.
func (c *WsTunnelClient) SetLogLevel(level string) {
	c.logLevel = level
}

// GetLogLevel retrieves diagnostic log levels filter tag.
func (c *WsTunnelClient) GetLogLevel() string {
	return c.logLevel
}
