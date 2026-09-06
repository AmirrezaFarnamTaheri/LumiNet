// Package scanner implements host and dns probing operations.

package scanner

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	gotls "crypto/tls"
)

// ─── Target Resolution ────────────────────────────────────────────────────────

// ResolveTargetCandidates resolves a target hostname or IP to a list of IP strings.
// IPv4 addresses are returned before IPv6. Bare IPs are returned as-is.
// Maps to upstream resolveTargetCandidates().
func ResolveTargetCandidates(target string) (ips []string, sni string, err error) {
	if net.ParseIP(target) != nil {
		return []string{target}, "", nil
	}
	resolved, lookupErr := net.LookupIP(target)
	if lookupErr != nil || len(resolved) == 0 {
		return nil, "", errors.New("DNS failed")
	}
	var out []string
	// IPv4 first
	for _, ip := range resolved {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	// Then IPv6
	for _, ip := range resolved {
		if ip.To4() == nil && ip.To16() != nil {
			out = append(out, ip.String())
		}
	}
	if len(out) == 0 {
		return nil, "", errors.New("no IP address")
	}
	return UniqueInOrder(out), target, nil
}

// ResolveTarget resolves a target and returns its first IP and SNI.
// Maps to upstream resolveTarget().
func ResolveTarget(target string) (ip, sni string, err error) {
	ips, resolvedSNI, err := ResolveTargetCandidates(target)
	if err != nil {
		return "", resolvedSNI, err
	}
	return ips[0], resolvedSNI, nil
}

// ─── SNI Candidate Building ───────────────────────────────────────────────────

// CandidateSNIs builds the ordered list of SNI candidates for probing.
// Maps to upstream candidateSNIs().
func CandidateSNIs(resolvedSNI string, corpus []string, multiSNI bool) []string {
	if multiSNI {
		candidates := make([]string, 0, len(corpus)+1)
		if strings.TrimSpace(resolvedSNI) != "" {
			candidates = append(candidates, resolvedSNI)
		}
		candidates = append(candidates, corpus...)
		return UniqueInOrder(candidates)
	}
	if strings.TrimSpace(resolvedSNI) != "" {
		return []string{resolvedSNI}
	}
	if len(corpus) > 0 {
		return []string{corpus[0]}
	}
	return []string{""}
}

// UniqueInOrder returns a deduplicated, ordered list of strings.
// Maps to upstream uniqueInOrder().
func UniqueInOrder(xs []string) []string {
	set := make(map[string]bool)
	var out []string
	for _, x := range xs {
		for _, part := range strings.FieldsFunc(x, func(r rune) bool {
			return r == ',' || r == ';' || r == '\r' || r == '\n' || r == '\t' || r == ' '
		}) {
			part = strings.TrimSpace(part)
			if part != "" && !set[part] {
				set[part] = true
				out = append(out, part)
			}
		}
	}
	return out
}

// ─── HTTP/1.1 Probe ───────────────────────────────────────────────────────────

// HTTP1ProbeResult holds the parsed response from an HTTP/1.1 HEAD probe.
type HTTP1ProbeResult struct {
	OK        bool
	Status    int
	Server    string
	Cache     string
	AltSvc    string
	HTTP3Hint bool
	ProbeCode string
}

// Getters & Setters for HTTP1ProbeResult
func (r *HTTP1ProbeResult) GetOK() bool           { return r.OK }
func (r *HTTP1ProbeResult) SetOK(v bool)          { r.OK = v }
func (r *HTTP1ProbeResult) GetStatus() int        { return r.Status }
func (r *HTTP1ProbeResult) SetStatus(v int)       { r.Status = v }
func (r *HTTP1ProbeResult) GetServer() string     { return r.Server }
func (r *HTTP1ProbeResult) SetServer(v string)    { r.Server = v }
func (r *HTTP1ProbeResult) GetCache() string      { return r.Cache }
func (r *HTTP1ProbeResult) SetCache(v string)     { r.Cache = v }
func (r *HTTP1ProbeResult) GetAltSvc() string     { return r.AltSvc }
func (r *HTTP1ProbeResult) SetAltSvc(v string)    { r.AltSvc = v }
func (r *HTTP1ProbeResult) GetHTTP3Hint() bool    { return r.HTTP3Hint }
func (r *HTTP1ProbeResult) SetHTTP3Hint(v bool)   { r.HTTP3Hint = v }
func (r *HTTP1ProbeResult) GetProbeCode() string  { return r.ProbeCode }
func (r *HTTP1ProbeResult) SetProbeCode(v string) { r.ProbeCode = v }

// ProbeHTTP1Conn performs an HTTP/1.1 HEAD probe over an existing raw connection.
// Maps to upstream httpProbeConn().
func ProbeHTTP1Conn(ctx context.Context, conn net.Conn, ip string, sni, path string, timeoutMS int) HTTP1ProbeResult {
	rollingDeadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
	_ = conn.SetDeadline(rollingDeadline)

	host := strings.TrimSpace(sni)
	if host == "" {
		host = ip
	}
	if path == "" {
		path = "/"
	}

	req := fmt.Sprintf(
		"HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: LumiNet/Scanner\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nX-LumiNet-Cachebuster: %d\r\nConnection: close\r\n\r\n",
		path, host, time.Now().UnixNano(),
	)
	if _, err := fmt.Fprint(conn, req); err != nil {
		return HTTP1ProbeResult{ProbeCode: ClassifyNetworkErrorStatic(err, "http")}
	}

	reader := io.LimitReader(conn, 64*1024)
	_ = conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))

	// Read status line
	statusLine, err := readLimitedLineFrom(reader, 4096)
	status := parseHTTPStatusLine(statusLine)
	if err != nil && errors.Is(err, io.EOF) && status > 0 {
		err = nil // Accept short responses that close immediately
	}
	if status == 0 {
		if err != nil {
			return HTTP1ProbeResult{ProbeCode: ClassifyNetworkErrorStatic(err, "http")}
		}
		return HTTP1ProbeResult{ProbeCode: "HTTP_PARSE_FAILED"}
	}

	server, cache, altSvc := "", "", ""
	if err == nil {
		for i := 0; i < 48; i++ {
			_ = conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
			header, hErr := readLimitedLineFrom(reader, 4096)
			if hErr != nil {
				if errors.Is(hErr, io.EOF) && strings.TrimSpace(header) == "" {
					break
				}
				return HTTP1ProbeResult{
					Status:    status,
					Server:    server,
					Cache:     cache,
					AltSvc:    altSvc,
					ProbeCode: ClassifyNetworkErrorStatic(hErr, "http"),
				}
			}
			header = strings.TrimRight(header, "\r\n")
			if strings.TrimSpace(header) == "" {
				break
			}
			lower := strings.ToLower(header)
			if strings.HasPrefix(lower, "server:") {
				server = strings.TrimSpace(header[len("server:"):])
			}
			if strings.HasPrefix(lower, "x-cache:") || strings.HasPrefix(lower, "cf-cache-status:") || strings.HasPrefix(lower, "age:") {
				if cache != "" {
					cache += "; "
				}
				cache += strings.TrimSpace(header)
			}
			if strings.HasPrefix(lower, "alt-svc:") {
				altSvc = strings.TrimSpace(header[len("alt-svc:"):])
			}
		}
	}

	http3Hint := strings.Contains(strings.ToLower(altSvc), "h3")
	ok := ctx.Err() == nil && status < 500
	return HTTP1ProbeResult{
		OK:        ok,
		Status:    status,
		Server:    server,
		Cache:     cache,
		AltSvc:    altSvc,
		HTTP3Hint: http3Hint,
	}
}

// ─── HTTP/2 Probe ─────────────────────────────────────────────────────────────

// ProbeHTTP2Conn performs an HTTP/2 HEAD probe over an existing TLS connection.
// Maps to upstream probeHTTPOverNegotiatedALPN() h2 branch.
func ProbeHTTP2Conn(ctx context.Context, conn net.Conn, ip, sni, path string, timeoutMS int) HTTP1ProbeResult {
	if path == "" {
		path = "/"
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMS) * time.Millisecond))

	// Wrap in a synthetic TLS connection for http2.Transport
	_, ok := conn.(*gotls.Conn)
	if !ok {
		return HTTP1ProbeResult{ProbeCode: "HTTP2_NOT_TLS_CONN"}
	}

	// Use net/http client via h2 transport on already-connected conn
	host := strings.TrimSpace(sni)
	if host == "" {
		host = ip
	}

	client := &http.Client{Timeout: time.Duration(timeoutMS) * time.Millisecond}
	httpReq, err := http.NewRequestWithContext(ctx, "HEAD", "https://"+host+path, nil)
	if err != nil {
		return HTTP1ProbeResult{ProbeCode: "HTTP2_REQ_FAILED"}
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return HTTP1ProbeResult{ProbeCode: ClassifyNetworkErrorStatic(err, "http2")}
	}
	defer func() { _ = resp.Body.Close() }()

	server := resp.Header.Get("Server")
	altSvc := resp.Header.Get("Alt-Svc")
	var cacheParts []string
	for _, key := range []string{"X-Cache", "CF-Cache-Status", "Age"} {
		if val := resp.Header.Get(key); val != "" {
			if key == "Age" {
				cacheParts = append(cacheParts, "Age: "+val)
			} else {
				cacheParts = append(cacheParts, val)
			}
		}
	}
	cache := strings.Join(cacheParts, "; ")
	status := resp.StatusCode
	http3Hint := strings.Contains(strings.ToLower(altSvc), "h3")
	return HTTP1ProbeResult{
		OK:        status < 500,
		Status:    status,
		Server:    server,
		Cache:     cache,
		AltSvc:    altSvc,
		HTTP3Hint: http3Hint,
	}
}

// ProbeHTTPOverALPN routes to HTTP/1.1 or HTTP/2 probe based on negotiated ALPN.
// Maps to upstream probeHTTPOverNegotiatedALPN().
func ProbeHTTPOverALPN(ctx context.Context, conn net.Conn, ip, sni, path, negotiatedALPN string, timeoutMS int) HTTP1ProbeResult {
	if strings.EqualFold(strings.TrimSpace(negotiatedALPN), "h2") {
		return ProbeHTTP2Conn(ctx, conn, ip, sni, path, timeoutMS)
	}
	return ProbeHTTP1Conn(ctx, conn, ip, sni, path, timeoutMS)
}

// ─── TLS Verification ─────────────────────────────────────────────────────────

// TLSPeerInfo holds extracted info from a completed TLS handshake.
// Maps to upstream tlsInfo struct.
type TLSPeerInfo struct {
	Version            string
	Cipher             string
	ALPN               string
	Verified           bool
	Subject            string
	Issuer             string
	ChainLength        int
	ChainBytes         int
	SignatureAlgorithm string
	PublicKeyAlgorithm string
}

// Getters & Setters for TLSPeerInfo
func (t *TLSPeerInfo) GetVersion() string             { return t.Version }
func (t *TLSPeerInfo) SetVersion(v string)            { t.Version = v }
func (t *TLSPeerInfo) GetCipher() string              { return t.Cipher }
func (t *TLSPeerInfo) SetCipher(v string)             { t.Cipher = v }
func (t *TLSPeerInfo) GetALPN() string                { return t.ALPN }
func (t *TLSPeerInfo) SetALPN(v string)               { t.ALPN = v }
func (t *TLSPeerInfo) GetVerified() bool              { return t.Verified }
func (t *TLSPeerInfo) SetVerified(v bool)             { t.Verified = v }
func (t *TLSPeerInfo) GetSubject() string             { return t.Subject }
func (t *TLSPeerInfo) SetSubject(v string)            { t.Subject = v }
func (t *TLSPeerInfo) GetIssuer() string              { return t.Issuer }
func (t *TLSPeerInfo) SetIssuer(v string)             { t.Issuer = v }
func (t *TLSPeerInfo) GetChainLength() int            { return t.ChainLength }
func (t *TLSPeerInfo) SetChainLength(v int)           { t.ChainLength = v }
func (t *TLSPeerInfo) GetChainBytes() int             { return t.ChainBytes }
func (t *TLSPeerInfo) SetChainBytes(v int)            { t.ChainBytes = v }
func (t *TLSPeerInfo) GetSignatureAlgorithm() string  { return t.SignatureAlgorithm }
func (t *TLSPeerInfo) SetSignatureAlgorithm(v string) { t.SignatureAlgorithm = v }
func (t *TLSPeerInfo) GetPublicKeyAlgorithm() string  { return t.PublicKeyAlgorithm }
func (t *TLSPeerInfo) SetPublicKeyAlgorithm(v string) { t.PublicKeyAlgorithm = v }

// ExtractTLSPeerInfo extracts TLS connection state into a TLSPeerInfo.
// Maps to upstream tlsProbeOpen() certificate extraction section.
func ExtractTLSPeerInfo(state gotls.ConnectionState, sni, remoteAddr string) TLSPeerInfo {
	info := TLSPeerInfo{
		Version: TLSVersionName(state.Version),
		Cipher:  CipherSuiteName(state.CipherSuite),
		ALPN:    state.NegotiatedProtocol,
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		info.ChainLength = len(state.PeerCertificates)
		for _, cert := range state.PeerCertificates {
			info.ChainBytes += len(cert.Raw)
		}
		info.Subject = leaf.Subject.String()
		info.Issuer = leaf.Issuer.String()
		info.SignatureAlgorithm = leaf.SignatureAlgorithm.String()
		info.PublicKeyAlgorithm = leaf.PublicKeyAlgorithm.String()

		verifyName := strings.TrimSpace(sni)
		if verifyName == "" {
			verifyName = remoteAddr
			if host, _, err := net.SplitHostPort(verifyName); err == nil {
				verifyName = host
			}
		}
		optsVerify := x509.VerifyOptions{
			DNSName:       verifyName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range state.PeerCertificates[1:] {
			optsVerify.Intermediates.AddCert(cert)
		}
		_, verifyErr := leaf.Verify(optsVerify)
		info.Verified = verifyErr == nil
	}
	return info
}

// TLSVersionName converts a TLS version uint16 to a human-readable string.
// Maps to upstream tlsVersionName() helper.
func TLSVersionName(v uint16) string {
	switch v {
	case gotls.VersionTLS10:
		return "TLS1.0"
	case gotls.VersionTLS11:
		return "TLS1.1"
	case gotls.VersionTLS12:
		return "TLS1.2"
	case gotls.VersionTLS13:
		return "TLS1.3"
	default:
		if v == 0 {
			return ""
		}
		return fmt.Sprintf("TLS_0x%04x", v)
	}
}

// CipherSuiteName converts a TLS cipher suite uint16 to a human-readable string.
// Maps to upstream cipherSuiteName() helper.
func CipherSuiteName(cs uint16) string {
	if name := gotls.CipherSuiteName(cs); name != "" {
		return name
	}
	return fmt.Sprintf("0x%04x", cs)
}

// ─── HTTP Status Parsing ──────────────────────────────────────────────────────

// parseHTTPStatusLine extracts the HTTP status code from a status line.
// Maps to upstream parseHTTPStatus() helper.
func parseHTTPStatusLine(line string) int {
	// e.g. "HTTP/1.1 200 OK"
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return 0
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 100 || code > 599 {
		return 0
	}
	return code
}

// readLimitedLineFrom reads one line from a LimitedReader up to maxLen bytes.
// Maps to upstream readLimitedLine() helper.
func readLimitedLineFrom(r io.Reader, maxLen int) (string, error) {
	buf := make([]byte, 0, 256)
	single := make([]byte, 1)
	for len(buf) < maxLen {
		n, err := r.Read(single)
		if n > 0 {
			buf = append(buf, single[0])
			if single[0] == '\n' {
				break
			}
		}
		if err != nil {
			return string(buf), err
		}
	}
	return string(buf), nil
}

// ─── TCP Probe ────────────────────────────────────────────────────────────────

// TCPProbe dials a TCP endpoint and returns true if it succeeds.
// Maps to upstream tcp() / tcpWithError() simplified form.
func TCPProbe(ctx context.Context, ip string, port, timeoutMS int) bool {
	network := "tcp4"
	if strings.Contains(ip, ":") {
		network = "tcp6"
	}
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond}
	conn, err := d.DialContext(ctx, network, target)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// TCPProbeWithError dials TCP and returns success + error.
// Maps to upstream tcpWithError() direct-dial branch.
func TCPProbeWithError(ctx context.Context, ip string, port, timeoutMS int) (bool, error) {
	network := "tcp4"
	if strings.Contains(ip, ":") {
		network = "tcp6"
	}
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond}
	conn, err := d.DialContext(ctx, network, target)
	if err != nil {
		return false, err
	}
	_ = conn.Close()
	return true, nil
}

// ─── TLS Dial ────────────────────────────────────────────────────────────────

// TLSDialResult is returned by TLSDial.
type TLSDialResult struct {
	Conn  *gotls.Conn
	TCPOK bool
	Info  TLSPeerInfo
	OK    bool
	Error error
}

// Getters & Setters for TLSDialResult
func (r *TLSDialResult) GetTCPOK() bool        { return r.TCPOK }
func (r *TLSDialResult) SetTCPOK(v bool)       { r.TCPOK = v }
func (r *TLSDialResult) GetOK() bool           { return r.OK }
func (r *TLSDialResult) SetOK(v bool)          { r.OK = v }
func (r *TLSDialResult) GetError() error       { return r.Error }
func (r *TLSDialResult) SetError(v error)      { r.Error = v }
func (r *TLSDialResult) GetInfo() TLSPeerInfo  { return r.Info }
func (r *TLSDialResult) SetInfo(v TLSPeerInfo) { r.Info = v }

// TLSDial dials a TCP connection and performs a standard TLS handshake.
// Unlike upstream (which uses utls/uconn), this uses stdlib TLS for portability.
// Maps to upstream dialUTLSWithALPN() standard-library variant.
func TLSDial(ctx context.Context, ip string, port int, sni string, timeoutMS int, nextProtos []string) TLSDialResult {
	network := "tcp4"
	if strings.Contains(ip, ":") {
		network = "tcp6"
	}
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond}
	rawConn, err := d.DialContext(ctx, network, target)
	if err != nil {
		return TLSDialResult{TCPOK: false, Error: err}
	}
	deadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
	_ = rawConn.SetDeadline(deadline)
	serverName := strings.TrimSpace(sni)
	cfg := &gotls.Config{
		ServerName:         serverName,
		MinVersion:         gotls.VersionTLS12,
		NextProtos:         nextProtos,
		InsecureSkipVerify: true, // scanner mode: measure, don't filter
	}
	if len(nextProtos) == 0 {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	tlsConn := gotls.Client(rawConn, cfg)

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = rawConn.Close()
		case <-done:
		}
	}()
	if hsErr := tlsConn.Handshake(); hsErr != nil {
		close(done)
		_ = rawConn.Close()
		return TLSDialResult{TCPOK: true, Error: hsErr}
	}
	close(done)
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = tlsConn.Close()
		return TLSDialResult{TCPOK: true, Error: ctxErr}
	}
	_ = tlsConn.SetDeadline(deadline)
	state := tlsConn.ConnectionState()
	info := ExtractTLSPeerInfo(state, sni, tlsConn.RemoteAddr().String())
	return TLSDialResult{Conn: tlsConn, TCPOK: true, Info: info, OK: true}
}
