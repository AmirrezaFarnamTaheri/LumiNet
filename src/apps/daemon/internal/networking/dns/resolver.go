package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/networking/geoip"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

// DoTEndpoint declares a strict DNS-over-TLS upstream. ServerName is mandatory
// so certificate authentication never degrades merely because Address is an IP.
type DoTEndpoint struct {
	Address    string
	ServerName string
}

// Resolver represents the Hybrid DNS Resolver.
type Resolver struct {
	server       *dns.Server
	listenAddr   string
	dohEndpoints []string
	dotEndpoints []DoTEndpoint
	regionalIPs  []string
	tunnelDomain string
	ProxyURL     string // SOCKS5/HTTP proxy URL
}

// NewResolver creates a new Hybrid DNS Resolver.
func NewResolver(listenAddr string, tunnelDomain string) *Resolver {
	return &Resolver{
		listenAddr:   listenAddr,
		dohEndpoints: []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"},
		dotEndpoints: []DoTEndpoint{
			{Address: "1.1.1.1:853", ServerName: "cloudflare-dns.com"},
			{Address: "8.8.8.8:853", ServerName: "dns.google"},
		},
		regionalIPs:  []string{"178.22.122.100", "10.202.10.10"}, // Shecan, Radar Game
		tunnelDomain: tunnelDomain,
	}
}

// Start launches the local UDP server.
func (r *Resolver) Start() error {
	r.server = &dns.Server{Addr: r.listenAddr, Net: "udp"}
	dns.HandleFunc(".", r.handleQuery)

	go func() {
		if err := r.server.ListenAndServe(); err != nil {
			fmt.Printf("DNS server failed to start on %s: %v\n", r.listenAddr, err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the server.
func (r *Resolver) Stop() error {
	if r.server != nil {
		return r.server.Shutdown()
	}
	return nil
}

// Resolve is the internal Go interface for our dialers.
func (r *Resolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	// 1. Check if domain is already a raw IP
	if ip := net.ParseIP(domain); ip != nil {
		return []net.IP{ip}, nil
	}

	// 2. Resolve local/LAN domain names directly using the system resolver
	if domain == "localhost" || strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".lan") {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		if domain == "localhost" {
			return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
		}
	}

	// Try DoH first
	ips, err := r.resolveDoH(ctx, domain)
	if err == nil && len(ips) > 0 {
		// Filter out local IPs resolved via public DoH to prevent DNS Rebinding attacks
		var cleanIPs []net.IP
		for _, ip := range ips {
			if !geoip.IsLocalOrLanIP(ip.String()) {
				cleanIPs = append(cleanIPs, ip)
			}
		}
		if len(cleanIPs) > 0 {
			return cleanIPs, nil
		}
	}

	// Try strict DNS-over-TLS next. When ProxyURL is a SOCKS5 endpoint this
	// becomes DoT-over-Tor/another SOCKS circuit without spawning proxychains.
	ips, err = r.resolveDoT(ctx, domain)
	if err == nil && len(ips) > 0 {
		var cleanIPs []net.IP
		for _, ip := range ips {
			if !geoip.IsLocalOrLanIP(ip.String()) {
				cleanIPs = append(cleanIPs, ip)
			}
		}
		if len(cleanIPs) > 0 {
			return cleanIPs, nil
		}
	}

	// Fallback to Regional
	ips, err = r.resolveRegional(ctx, domain)
	if err == nil && len(ips) > 0 {
		return ips, nil
	}

	// Fallback to LowerBase36 Tunnel
	return r.resolveTunnel(ctx, domain)
}

// LookupEncryptedA performs an A-record lookup using only authenticated
// encrypted DNS transports (DoH, then strict DoT). Unlike Resolve, it does not
// apply the public-DNS rebinding filter because diagnostic DNS protocols such
// as Tor DNSEL intentionally return loopback addresses. Callers must therefore
// treat the result as evidence, never as a connection target.
func (r *Resolver) LookupEncryptedA(ctx context.Context, domain string) ([]net.IP, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" || net.ParseIP(domain) != nil || strings.ContainsAny(domain, "\\/\r\n\x00") {
		return nil, fmt.Errorf("invalid encrypted DNS name %q", domain)
	}
	ips, err := r.resolveDoH(ctx, domain)
	if err == nil && len(ips) > 0 {
		return cloneIPs(ips), nil
	}
	if isDNSNotFound(err) {
		return nil, err
	}
	dohErr := err
	ips, err = r.resolveDoT(ctx, domain)
	if err == nil && len(ips) > 0 {
		return cloneIPs(ips), nil
	}
	if isDNSNotFound(err) {
		return nil, err
	}
	return nil, errors.Join(dohErr, err)
}

func cloneIPs(in []net.IP) []net.IP {
	out := make([]net.IP, len(in))
	for i, ip := range in {
		out[i] = append(net.IP(nil), ip...)
	}
	return out
}

func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func (r *Resolver) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	if len(req.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := req.Question[0]
	domain := strings.TrimSuffix(q.Name, ".")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := r.Resolve(ctx, domain)
	if err == nil {
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, ip4.String()))
				if rr != nil {
					m.Answer = append(m.Answer, rr)
				}
			} else {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA %s", q.Name, ip.String()))
				if rr != nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}

	w.WriteMsg(m)
}

func (r *Resolver) resolveDoH(ctx context.Context, domain string) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	msgBytes, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	// Create custom transport with dohot privacy settings (no session tickets, secure ciphers)
	tlsConfig := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if err := r.configureDoHProxy(transport); err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var lastErr error

	for _, endpoint := range r.dohEndpoints {
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(msgBytes))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("DoH HTTP status %d", resp.StatusCode)
			continue
		}

		respBytes, readErr := readBoundedDNSBody(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if closeErr != nil {
			lastErr = closeErr
			continue
		}

		respMsg := new(dns.Msg)
		if err := respMsg.Unpack(respBytes); err != nil {
			lastErr = err
			continue
		}
		if respMsg.Rcode == dns.RcodeNameError {
			return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
		}
		if respMsg.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DoH returned rcode %d", respMsg.Rcode)
			continue
		}

		var ips []net.IP
		for _, rr := range respMsg.Answer {
			if aRecord, ok := rr.(*dns.A); ok {
				ips = append(ips, aRecord.A)
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("DoH resolution returned no IPs")
}

func (r *Resolver) configureDoHProxy(transport *http.Transport) error {
	if strings.TrimSpace(r.ProxyURL) == "" {
		return nil
	}
	proxyURL, err := url.Parse(r.ProxyURL)
	if err != nil {
		return fmt.Errorf("parse DoH proxy: %w", err)
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "socks5":
		base := &net.Dialer{Timeout: 3 * time.Second}
		dialer, err := proxy.FromURL(proxyURL, base)
		if err != nil {
			return fmt.Errorf("create DoH SOCKS5 dialer: %w", err)
		}
		if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
			transport.DialContext = contextDialer.DialContext
			return nil
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			type result struct {
				conn net.Conn
				err  error
			}
			ch := make(chan result, 1)
			go func() {
				conn, err := dialer.Dial(network, addr)
				if ctx.Err() != nil && conn != nil {
					_ = conn.Close()
					conn = nil
					err = ctx.Err()
				}
				ch <- result{conn: conn, err: err}
			}()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case got := <-ch:
				return got.conn, got.err
			}
		}
		return nil
	case "http", "https":
		if proxyURL.Host == "" {
			return fmt.Errorf("DoH proxy requires a host")
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		return nil
	default:
		return fmt.Errorf("unsupported DoH proxy scheme %q", proxyURL.Scheme)
	}
}

func (r *Resolver) resolveDoT(ctx context.Context, domain string) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	var lastErr error
	for _, endpoint := range r.dotEndpoints {
		if err := validateDoTEndpoint(endpoint); err != nil {
			lastErr = err
			continue
		}
		raw, err := r.dialDoTRaw(ctx, endpoint.Address, 3*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		tlsConn := tls.Client(raw, &tls.Config{
			ServerName:             endpoint.ServerName,
			MinVersion:             tls.VersionTLS12,
			SessionTicketsDisabled: true,
		})
		deadline := time.Now().Add(3 * time.Second)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		_ = tlsConn.SetDeadline(deadline)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			lastErr = fmt.Errorf("DoT TLS handshake %s: %w", endpoint.Address, err)
			continue
		}
		dnsConn := &dns.Conn{Conn: tlsConn}
		if err := dnsConn.WriteMsg(msg); err != nil {
			_ = dnsConn.Close()
			lastErr = fmt.Errorf("DoT write %s: %w", endpoint.Address, err)
			continue
		}
		resp, err := dnsConn.ReadMsg()
		_ = dnsConn.Close()
		if err != nil {
			lastErr = fmt.Errorf("DoT read %s: %w", endpoint.Address, err)
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("DoT %s returned no response", endpoint.Address)
			continue
		}
		if resp.Rcode == dns.RcodeNameError {
			return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
		}
		if resp.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DoT %s returned rcode %d", endpoint.Address, resp.Rcode)
			continue
		}
		var ips []net.IP
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips = append(ips, append(net.IP(nil), a.A...))
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
		lastErr = fmt.Errorf("DoT %s returned no A records", endpoint.Address)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no DoT endpoints configured")
}

func validateDoTEndpoint(endpoint DoTEndpoint) error {
	if strings.TrimSpace(endpoint.Address) == "" || strings.TrimSpace(endpoint.ServerName) == "" {
		return fmt.Errorf("DoT endpoint requires address and TLS server name")
	}
	host, port, err := net.SplitHostPort(endpoint.Address)
	if err != nil || strings.TrimSpace(host) == "" || port != "853" {
		return fmt.Errorf("invalid DoT endpoint %q", endpoint.Address)
	}
	if strings.ContainsAny(endpoint.ServerName, "\r\n\x00/\\") {
		return fmt.Errorf("invalid DoT TLS server name")
	}
	return nil
}

func (r *Resolver) dialDoTRaw(ctx context.Context, address string, timeout time.Duration) (net.Conn, error) {
	base := &net.Dialer{Timeout: timeout}
	if strings.TrimSpace(r.ProxyURL) == "" {
		return base.DialContext(ctx, "tcp", address)
	}
	proxyURL, err := url.Parse(r.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse DoT proxy: %w", err)
	}
	if proxyURL.Scheme != "socks5" {
		return nil, fmt.Errorf("DoT proxy must use socks5, got %q", proxyURL.Scheme)
	}
	dialer, err := proxy.FromURL(proxyURL, base)
	if err != nil {
		return nil, fmt.Errorf("create DoT SOCKS5 dialer: %w", err)
	}
	if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
		return contextDialer.DialContext(ctx, "tcp", address)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := dialer.Dial("tcp", address)
		if ctx.Err() != nil && conn != nil {
			_ = conn.Close()
			conn = nil
			err = ctx.Err()
		}
		ch <- result{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case got := <-ch:
		return got.conn, got.err
	}
}

func (r *Resolver) resolveRegional(ctx context.Context, domain string) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	client := new(dns.Client)
	client.Timeout = 2 * time.Second

	var lastErr error
	for _, ip := range r.regionalIPs {
		var targetAddr string
		if strings.Contains(ip, ":") {
			targetAddr = ip
		} else {
			targetAddr = net.JoinHostPort(ip, "53")
		}
		resp, _, err := client.ExchangeContext(ctx, msg, targetAddr)
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			var ips []net.IP
			for _, rr := range resp.Answer {
				if aRecord, ok := rr.(*dns.A); ok {
					ips = append(ips, aRecord.A)
				}
			}
			if len(ips) > 0 {
				return ips, nil
			}
		} else if err != nil {
			lastErr = err
		} else if resp == nil {
			lastErr = fmt.Errorf("regional DNS %s returned no response", targetAddr)
		} else {
			lastErr = fmt.Errorf("regional DNS %s returned rcode %d", targetAddr, resp.Rcode)
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("regional resolution returned no IPs")
}

func (r *Resolver) resolveTunnel(ctx context.Context, domain string) ([]net.IP, error) {
	if r.tunnelDomain == "" {
		return nil, fmt.Errorf("tunnel domain not configured")
	}

	// Encode domain request into LowerBase36
	encoded := Encode([]byte(domain))
	queryDomain := fmt.Sprintf("%s.%s", encoded, r.tunnelDomain)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(queryDomain), dns.TypeA)

	client := new(dns.Client)
	client.Timeout = 3 * time.Second

	var lastErr error
	dnsServers := append(r.regionalIPs, "8.8.8.8", "1.1.1.1")
	for _, server := range dnsServers {
		var targetAddr string
		if strings.Contains(server, ":") {
			targetAddr = server
		} else {
			targetAddr = net.JoinHostPort(server, "53")
		}
		resp, _, err := client.ExchangeContext(ctx, msg, targetAddr)
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			var ips []net.IP
			for _, rr := range resp.Answer {
				if aRecord, ok := rr.(*dns.A); ok {
					ips = append(ips, aRecord.A)
				}
			}
			if len(ips) > 0 {
				return ips, nil
			}
		} else {
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("tunnel resolution returned no IPs")
}
