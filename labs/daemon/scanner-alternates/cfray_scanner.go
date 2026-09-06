// Package scanner implements host and dns probing operations.
// Ported from: cfray-main (scanner.py)
// Target path: server/internal/scanner/cfray_scanner.go

package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CFrayProbeResult holds the scan outcome for a potential Cloudflare edge IP.
type CFrayProbeResult struct {
	IP          string        `json:"ip"`
	Port        int           `json:"port"`
	StatusCode  int           `json:"status_code"`
	Server      string        `json:"server"`
	HTTPVersion string        `json:"http_version"`
	Latency     time.Duration `json:"latency"`
	IsCF        bool          `json:"is_cf"`
	TLSVersion  uint16        `json:"tls_version,omitempty"`
	CipherSuite uint16        `json:"cipher_suite,omitempty"`
	Negotiated  string        `json:"negotiated,omitempty"` // ALPN
	Error       string        `json:"error,omitempty"`
}

// Getters & Setters for CFrayProbeResult
func (r *CFrayProbeResult) GetIP() string { return r.IP }
func (r *CFrayProbeResult) SetIP(v string) { r.IP = v }

// CFrayScanner scans a range of IPs to check if they are valid Cloudflare CDN fronting points.
type CFrayScanner struct {
	targetDomain string
	ports        []int
	timeout      time.Duration
}

// NewCFrayScanner creates a CFrayScanner.
func NewCFrayScanner(targetDomain string, ports []int, timeout time.Duration) *CFrayScanner {
	if len(ports) == 0 {
		ports = []int{443}
	}
	return &CFrayScanner{
		targetDomain: targetDomain,
		ports:        ports,
		timeout:      timeout,
	}
}

// ScanIPs probes candidate IPs in parallel.
// Maps to python threadpool runner in scanner.py.
func (s *CFrayScanner) ScanIPs(ctx context.Context, ips []string, concurrency int) []CFrayProbeResult {
	if concurrency <= 0 {
		concurrency = 50
	}

	results := make([]CFrayProbeResult, 0, len(ips)*len(s.ports))
	mu := sync.Mutex{}
	sem := make(chan struct{}, concurrency)
	wg := sync.WaitGroup{}

	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	for _, ip := range ips {
		for _, port := range s.ports {
			wg.Add(1)
			sem <- struct{}{}
			go func(targetIP string, targetPort int) {
				defer wg.Done()
				defer func() { <-sem }()

				res := s.probeSingle(ctx, dialer, targetIP, targetPort)
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
			}(ip, port)
		}
	}

	wg.Wait()
	return results
}

func (s *CFrayScanner) probeSingle(ctx context.Context, dialer *net.Dialer, ip string, port int) CFrayProbeResult {
	start := time.Now()
	res := CFrayProbeResult{
		IP:   ip,
		Port: port,
		IsCF: false,
	}

	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	scheme := "http"
	isTLS := port == 443 || port == 2053 || port == 2083 || port == 2087 || port == 2096 || port == 8443
	if isTLS {
		scheme = "https"
	}

	// Prepare Custom Dialer to inspect TLS handshake
	dialContext := func(c context.Context, network, _ string) (net.Conn, error) {
		conn, err := dialer.DialContext(c, "tcp", addr)
		if err != nil {
			return nil, err
		}

		if isTLS {
			// Do a manual handshake to inspect TLS connection stats
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         s.targetDomain,
				InsecureSkipVerify: true, // We check CDN reachability, cert validity will be checked by Host
				NextProtos:         []string{"h2", "http/1.1"},
			})
			err = tlsConn.HandshakeContext(c)
			if err != nil {
				conn.Close()
				return nil, err
			}
			state := tlsConn.ConnectionState()
			res.TLSVersion = state.Version
			res.CipherSuite = state.CipherSuite
			res.Negotiated = state.NegotiatedProtocol
			return tlsConn, nil
		}
		return conn, nil
	}

	transport := &http.Transport{
		DialContext:         dialContext,
		TLSHandshakeTimeout: s.timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   s.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	reqURL := fmt.Sprintf("%s://%s/", scheme, s.targetDomain)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	res.Server = resp.Header.Get("Server")
	res.HTTPVersion = resp.Proto
	res.Latency = time.Since(start)

	serverLower := strings.ToLower(res.Server)
	if strings.Contains(serverLower, "cloudflare") || resp.Header.Get("cf-ray") != "" {
		res.IsCF = true
	}

	return res
}
