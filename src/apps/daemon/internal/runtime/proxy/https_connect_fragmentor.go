package proxy

// MahsaNG-derived: HTTPS CONNECT fragmentor proxy with integrated DoH-over-Fragment.
// Source: MahsaNG/V2rayNG/gfwknocker/{HTTPS_Fragmentor.kt, DoH_over_Fragment.kt}
// Architecture: local HTTPS CONNECT proxy listener → fragments first request packet into
// num_fragment chunks with fragment_sleep_ms delay between each → DPI circumvention.
// DoH integration: if target_ip is empty, resolves hostname via DoH JSON API before connecting.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/maybeknott/luminet/internal/foundation/boundedio"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// httpsFragmentorSocketTimeout is the max idle time per socket (matches Mahsa's myH_socket_timeout=8s).
	httpsFragmentorSocketTimeout = 8 * time.Second
	// httpsFragmentorFirstPacketWait is the delay before reading the first upstream packet (100ms in Mahsa).
	httpsFragmentorFirstPacketWait = 100 * time.Millisecond
	// dohQueryType A record type number used in DoH JSON API response parsing.
	dohQueryTypeA = 1
)

// HTTPSFragmentorConfig configures the HTTPS CONNECT fragmentor.
type HTTPSFragmentorConfig struct {
	ListenAddr    string               // e.g. "127.0.0.1:4500"
	TargetAddr    string               // override all CONNECT destinations to this addr (empty = use CONNECT header)
	NumFragments  int                  // number of TCP fragments to split the first packet into
	FragmentSleep time.Duration        // delay between fragments (e.g. 10ms)
	DoHResolver   *DoHFragmentResolver // nil = no DoH, use direct DNS
}

// DoHFragmentResolverConfig configures DNS-over-HTTPS via a fragmented HTTPS proxy.
type DoHFragmentResolverConfig struct {
	// DoHURL is the base DNS JSON URL, e.g. "https://dns.google/resolve?name="
	// Shortcuts: "google" → dns.google, "cloudflare" → cloudflare-dns.com
	DoHURL string
	// OfflineDNS pre-seeds the resolver cache (domain → IP).
	OfflineDNS map[string]string
}

// DoHFragmentResolver resolves domain names via DoH JSON API, caching results.
// It routes its own HTTPS queries through an HTTPS fragmentor to evade DPI.
type DoHFragmentResolver struct {
	mu        sync.RWMutex
	cache     map[string]string
	dohURL    string
	transport *http.Transport
}

// NewDoHFragmentResolver creates a DoHFragmentResolver that sends its HTTPS queries
// through a local HTTPS CONNECT proxy (proxyAddr) to bypass DPI.
// offlineDNS pre-populates the cache (e.g. {"cloudflare-dns.com":"104.16.133.229"}).
func NewDoHFragmentResolver(dohURL string, proxyAddr string, offlineDNS map[string]string) *DoHFragmentResolver {
	resolved := dohURL
	switch dohURL {
	case "", "google":
		resolved = "https://dns.google/resolve?name="
	case "cloudflare":
		resolved = "https://cloudflare-dns.com/dns-query?name="
	}

	proxy := func(_ *http.Request) (*url.URL, error) {
		if proxyAddr == "" {
			return nil, nil
		}
		return url.Parse("http://" + proxyAddr)
	}

	transport := &http.Transport{
		Proxy:               proxy,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   8 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	cache := make(map[string]string)
	for k, v := range offlineDNS {
		cache[k] = v
	}

	return &DoHFragmentResolver{
		cache:     cache,
		dohURL:    resolved,
		transport: transport,
	}
}

// Resolve returns the first A-record IP for the domain, using the cache first.
// Returns ("", false) if resolution fails.
func (r *DoHFragmentResolver) Resolve(domain string) (string, bool) {
	// Check cache first
	r.mu.RLock()
	if ip, ok := r.cache[domain]; ok {
		r.mu.RUnlock()
		return ip, true
	}
	r.mu.RUnlock()

	// Build DoH JSON API URL: https://dns.google/resolve?name=<domain>&type=A&ct=application%2Fdns-json
	queryURL := fmt.Sprintf("%s%s&type=A&ct=application%%2Fdns-json", r.dohURL, url.QueryEscape(domain))

	client := &http.Client{Transport: r.transport, Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", queryURL, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return "", false
	}

	// Parse DoH JSON response: {"Answer":[{"type":1,"data":"1.2.3.4"},...]}
	var dohResp struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return "", false
	}

	for _, ans := range dohResp.Answer {
		if ans.Type == dohQueryTypeA && ans.Data != "" {
			r.mu.Lock()
			r.cache[domain] = ans.Data
			r.mu.Unlock()
			return ans.Data, true
		}
	}
	return "", false
}

// HTTPSConnectFragmentor is a local HTTPS CONNECT proxy that fragments the first
// upstream request packet into NumFragments TCP segments to evade DPI.
// Optionally integrates DoH-over-Fragment for hostname resolution.
type HTTPSConnectFragmentor struct {
	cfg      HTTPSFragmentorConfig
	listener net.Listener
	mu       sync.Mutex
	ready    chan struct{}
}

// NewHTTPSConnectFragmentor creates an HTTPSConnectFragmentor from the given config.
func NewHTTPSConnectFragmentor(cfg HTTPSFragmentorConfig) *HTTPSConnectFragmentor {
	if cfg.NumFragments < 2 {
		cfg.NumFragments = 2
	}
	if cfg.FragmentSleep == 0 {
		cfg.FragmentSleep = 10 * time.Millisecond
	}
	return &HTTPSConnectFragmentor{
		cfg:   cfg,
		ready: make(chan struct{}),
	}
}

// ListenAddr returns the actual listening address after Start() is called.
func (f *HTTPSConnectFragmentor) ListenAddr() string {
	<-f.ready
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listener != nil {
		return f.listener.Addr().String()
	}
	return ""
}

// Start launches the HTTPS CONNECT proxy in the background.
func (f *HTTPSConnectFragmentor) Start() error {
	ln, err := net.Listen("tcp", f.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("HTTPSConnectFragmentor: listen on %q failed: %w", f.cfg.ListenAddr, err)
	}
	f.mu.Lock()
	f.listener = ln
	f.mu.Unlock()
	close(f.ready)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handleConn(conn)
		}
	}()
	return nil
}

// Stop shuts down the fragmentor listener.
func (f *HTTPSConnectFragmentor) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listener != nil {
		_ = f.listener.Close()
	}
}

var ipv4Pattern = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

func (f *HTTPSConnectFragmentor) handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(httpsFragmentorSocketTimeout))

	// Read CONNECT/GET/POST header (wait 10ms for full packet like Mahsa)
	time.Sleep(10 * time.Millisecond)
	buf := make([]byte, 8192)
	n, err := clientConn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	data := string(buf[:n])
	lines := strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return
	}

	method := parts[0]
	rhost := parts[1]

	var targetHost string
	var targetPort string

	switch method {
	case "CONNECT":
		// Honor TargetAddr override, or extract from CONNECT header
		if f.cfg.TargetAddr != "" {
			targetHost, targetPort, _ = net.SplitHostPort(f.cfg.TargetAddr)
		} else {
			targetHost, targetPort, err = net.SplitHostPort(rhost)
			if err != nil {
				targetHost = rhost
				targetPort = "443"
			}
		}
	case "GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE":
		// Redirect HTTP → HTTPS
		redirectURL := strings.Replace(rhost, "http://", "https://", 1)
		resp := fmt.Sprintf("HTTP/1.1 302 Found\r\nLocation: %s\r\nProxy-agent: LumiNetProxy/1.0\r\n\r\n", redirectURL)
		_, _ = clientConn.Write([]byte(resp))
		return
	default:
		_, _ = clientConn.Write([]byte("HTTP/1.1 400 Bad Request\r\nProxy-agent: LumiNetProxy/1.0\r\n\r\n"))
		return
	}

	// Resolve hostname via DoH if needed
	if f.cfg.DoHResolver != nil && !ipv4Pattern.MatchString(targetHost) {
		if resolved, ok := f.cfg.DoHResolver.Resolve(targetHost); ok {
			targetHost = resolved
		}
	}

	// Connect to backend
	backendConn, err := net.DialTimeout("tcp",
		net.JoinHostPort(targetHost, targetPort),
		httpsFragmentorSocketTimeout)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nProxy-agent: LumiNetProxy/1.0\r\n\r\n"))
		return
	}
	defer backendConn.Close()
	_ = backendConn.SetDeadline(time.Now().Add(httpsFragmentorSocketTimeout))

	// Send CONNECT established response
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\nProxy-agent: LumiNetProxy/1.0\r\n\r\n"))

	// Start downstream goroutine (backend → client)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ioBidirectionalCopy(clientConn, backendConn)
	}()

	// Upstream: client → backend, fragment first packet
	time.Sleep(httpsFragmentorFirstPacketWait)
	upBuf := make([]byte, 8192)
	for first := true; ; first = false {
		nr, err := clientConn.Read(upBuf)
		if nr > 0 {
			if first {
				if werr := sendFragmented(backendConn, upBuf[:nr], f.cfg.NumFragments, f.cfg.FragmentSleep); werr != nil {
					break
				}
			} else {
				if _, werr := backendConn.Write(upBuf[:nr]); werr != nil {
					break
				}
			}
		}
		if err != nil {
			break
		}
	}
	<-done
}

// ioBidirectionalCopy copies from src to dst until EOF.
func ioBidirectionalCopy(dst, src net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// sendFragmented splits data into numFragments TCP segments with sleepBetween delay,
// using the same pickKRandomInts partitioning algorithm as MahsaNG.
func sendFragmented(conn net.Conn, data []byte, numFragments int, sleepBetween time.Duration) error {
	L := len(data)
	if L == 0 {
		return nil
	}
	indices := PickKRandomInts(numFragments-1, L)
	prev := 0
	for _, idx := range indices {
		if _, err := conn.Write(data[prev:idx]); err != nil {
			return err
		}
		time.Sleep(sleepBetween)
		prev = idx
	}
	_, err := conn.Write(data[prev:])
	return err
}

// WaitForLocalPort polls localhost:port until it accepts a TCP connection or ctx expires.
// Derived from MahsaNG PsiphonVpnService.waitForPort() with 500ms check interval and
// configurable timeout.
func WaitForLocalPort(ctx context.Context, port int, interval, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return true
			}
			if time.Now().After(deadline) {
				return false
			}
		}
	}
}

// PsiphonTunnelProtocol selects the Psiphon tunnel protocol set.
type PsiphonTunnelProtocol string

const (
	PsiphonProtocolAuto    PsiphonTunnelProtocol = "auto"
	PsiphonProtocolNormal  PsiphonTunnelProtocol = "normal"  // SSH, OSSH, TLS-OSSH, QUIC-OSSH, SHADOWSOCKS-OSSH
	PsiphonProtocolConduit PsiphonTunnelProtocol = "conduit" // INPROXY-WEBRTC-* variants
)

// PsiphonTunnelConfig holds the full Psiphon JSON configuration parameters
// derived from MahsaNG's getPsiphonConfig() method.
type PsiphonTunnelConfig struct {
	// UpstreamProxyURL is set when chaining V2Ray behind Psiphon (e.g. "socks5://127.0.0.1:10808")
	UpstreamProxyURL string
	// EgressRegion selects a Psiphon exit region (2-letter ISO country code, or "" for any)
	EgressRegion string
	// AggressiveEstablishment enables aggressive multi-protocol parallel connection attempts
	AggressiveEstablishment bool
	// Protocol selects the allowed tunnel protocol set
	Protocol PsiphonTunnelProtocol
	// LocalSocksPort is the Psiphon local SOCKS5 proxy port (default 1080)
	LocalSocksPort int
	// LocalHTTPPort is the Psiphon local HTTP proxy port (default 8080)
	LocalHTTPPort int
	// DNSResolverAlternateServers is the fallback DNS list Psiphon uses internally
	DNSResolverAlternateServers []string
	// DataRootDirectory is the path for Psiphon data files
	DataRootDirectory string
	// PropagationChannelId and SponsorId must be set (use "FFFFFFFFFFFFFFFF" for dev)
	PropagationChannelId string
	SponsorId            string
	// EstablishTunnelTimeoutSeconds (0 = no timeout)
	EstablishTunnelTimeoutSeconds int
}

// DefaultPsiphonTunnelConfig returns a default configuration suitable for development/testing.
func DefaultPsiphonTunnelConfig() *PsiphonTunnelConfig {
	return &PsiphonTunnelConfig{
		Protocol:                      PsiphonProtocolAuto,
		LocalSocksPort:                1080,
		LocalHTTPPort:                 8080,
		PropagationChannelId:          "FFFFFFFFFFFFFFFF",
		SponsorId:                     "FFFFFFFFFFFFFFFF",
		EstablishTunnelTimeoutSeconds: 0, // no timeout — keep trying
		DNSResolverAlternateServers: []string{
			"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
		},
	}
}

// NormalProtocols returns the list of allowed Psiphon protocol strings for PsiphonProtocolNormal.
// Source: MahsaNG PsiphonVpnService.getPsiphonConfig() "normal" branch.
func NormalProtocols() []string {
	return []string{"SSH", "OSSH", "TLS-OSSH", "QUIC-OSSH", "SHADOWSOCKS-OSSH"}
}

// ConduitProtocols returns the INPROXY WebRTC protocol list for PsiphonProtocolConduit.
// Source: MahsaNG PsiphonVpnService.getPsiphonConfig() "conduit" branch.
func ConduitProtocols() []string {
	return []string{
		"INPROXY-WEBRTC-OSSH",
		"INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH",
		"INPROXY-WEBRTC-UNFRONTED-MEEK-SESSION-TICKET-OSSH",
		"INPROXY-WEBRTC-FRONTED-MEEK-OSSH",
		"INPROXY-WEBRTC-FRONTED-MEEK-HTTP-OSSH",
		"INPROXY-WEBRTC-QUIC-OSSH",
	}
}

// MarshalPsiphonConfig serializes a PsiphonTunnelConfig to the JSON string expected
// by the Psiphon tunnel-core library's PsiphonTunnel.startTunneling() call.
func MarshalPsiphonConfig(cfg *PsiphonTunnelConfig) (string, error) {
	m := map[string]interface{}{
		"PropagationChannelId":            cfg.PropagationChannelId,
		"SponsorId":                       cfg.SponsorId,
		"LocalSocksProxyPort":             cfg.LocalSocksPort,
		"LocalHttpProxyPort":              cfg.LocalHTTPPort,
		"EmitDiagnosticNotices":           true,
		"EmitDiagnosticNetworkParameters": true,
		"EmitBytesTransferred":            true,
		"EmitServerAlerts":                true,
		"EstablishTunnelTimeoutSeconds":   cfg.EstablishTunnelTimeoutSeconds,
		"DNSResolverAlternateServers":     cfg.DNSResolverAlternateServers,
	}
	if cfg.DataRootDirectory != "" {
		m["DataRootDirectory"] = cfg.DataRootDirectory
	}
	if cfg.UpstreamProxyURL != "" {
		m["UpstreamProxyURL"] = cfg.UpstreamProxyURL
	}
	if len(cfg.EgressRegion) == 2 {
		m["EgressRegion"] = cfg.EgressRegion
	}
	if cfg.AggressiveEstablishment {
		m["AggressiveEstablishment"] = true
	}
	switch cfg.Protocol {
	case PsiphonProtocolNormal:
		m["LimitTunnelProtocols"] = NormalProtocols()
	case PsiphonProtocolConduit:
		m["LimitTunnelProtocols"] = ConduitProtocols()
	}

	data, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("MarshalPsiphonConfig: %w", err)
	}
	return string(data), nil
}

// ResponseLineReader reads a line-terminated response from an HTTP CONNECT proxy
// (used in testing and manual CONNECT tunnel scenarios).
func ResponseLineReader(conn net.Conn) (string, error) {
	br := bufio.NewReader(conn)
	line, err := boundedio.ReadLine(br, 16<<10)
	return strings.TrimSpace(line), err
}
