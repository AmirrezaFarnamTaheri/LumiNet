package diagnostics

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type CDNDiscoveryEngine struct {
	Concurrency int
	Timeout     time.Duration
}

func NewCDNDiscoveryEngine() *CDNDiscoveryEngine {
	return &CDNDiscoveryEngine{
		Concurrency: 50,
		Timeout:     3 * time.Second,
	}
}

// DiscoverCleanIPs scans candidate IPs concurrently and verifies them using Host header and HTML title matching.
func (e *CDNDiscoveryEngine) DiscoverCleanIPs(ctx context.Context, host string, candidateIPs []string, expectedTitle string) ([]string, error) {
	if len(candidateIPs) == 0 {
		// Fallback to DNS resolve
		resolver := &net.Resolver{}
		ips, err := resolver.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		candidateIPs = ips
	}

	var cleanIPs []string
	var mu sync.Mutex

	sem := make(chan struct{}, e.Concurrency)
	var wg sync.WaitGroup

	for _, ip := range candidateIPs {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			if e.verifyIP(ctx, targetIP, host, expectedTitle) {
				mu.Lock()
				cleanIPs = append(cleanIPs, targetIP)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return cleanIPs, nil
}

func (e *CDNDiscoveryEngine) verifyIP(ctx context.Context, ip string, host string, expectedTitle string) bool {
	transport := &http.Transport{
		DialTLSContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: e.Timeout}
			addr := ip
			if _, _, err := net.SplitHostPort(ip); err != nil {
				addr = net.JoinHostPort(ip, "443")
			}
			conn, err := dialer.DialContext(dialCtx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			tlsConfig := &tls.Config{
				ServerName: host,
				// Probing candidate fronting IPs intentionally skips chain
				// validation: mirrors and clean-origin mirrors frequently
				// present mismatched or self-signed certificates, and the
				// signal here is the served title, not PKI identity.
				InsecureSkipVerify: true,
			}
			tlsConn := tls.Client(conn, tlsConfig)
			err = tlsConn.HandshakeContext(dialCtx)
			if err != nil {
				conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   e.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+host, nil)
	if err != nil {
		return false
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false
	}

	// HTML Title comparison
	if expectedTitle != "" {
		titleRegexp := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
		matches := titleRegexp.FindSubmatch(bodyBytes)
		if len(matches) < 2 {
			return false
		}
		actualTitle := strings.TrimSpace(string(matches[1]))
		if !strings.Contains(strings.ToLower(actualTitle), strings.ToLower(expectedTitle)) {
			return false
		}
	}

	return true
}
