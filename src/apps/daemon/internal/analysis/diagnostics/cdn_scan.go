package diagnostics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// CdnScanResult represents the detailed result of scanning a CDN edge IP.
type CdnScanResult struct {
	IP        string  `json:"ip"`
	Alive     bool    `json:"alive"`
	LatencyMs float64 `json:"latency_ms"`
	HTTPCode  int     `json:"http_code,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// ScanCdnIP sweeps edge IP subnet ranges to discover unblocked servers for domain fronting.
func ScanCdnIP(ip string, testHost string) bool {
	dialer := &net.Dialer{Timeout: 1 * time.Second}
	uConn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false
	}

	tlsConfig := &utls.Config{
		ServerName: testHost,
	}

	utlsConn := utls.UClient(uConn, tlsConfig, utls.HelloChrome_Auto)
	if err := utlsConn.Handshake(); err != nil {
		uConn.Close()
		return false
	}
	defer utlsConn.Close()
	return true
}

// ScanCdnIPDetailed performs a detailed TLS handshake and HTTP fronting test on a CDN edge IP.
func ScanCdnIPDetailed(ip string, testHost string, timeout time.Duration) CdnScanResult {
	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}

	// 1. Verify TLS Handshake
	uConn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return CdnScanResult{
			IP:    ip,
			Alive: false,
			Error: err.Error(),
		}
	}

	tlsConfig := &utls.Config{
		ServerName: testHost,
	}

	utlsConn := utls.UClient(uConn, tlsConfig, utls.HelloChrome_Auto)
	if err := utlsConn.Handshake(); err != nil {
		uConn.Close()
		return CdnScanResult{
			IP:    ip,
			Alive: false,
			Error: err.Error(),
		}
	}
	utlsConn.Close()

	latency := time.Since(start).Seconds() * 1000.0

	// 2. Verify HTTP Fronting / Cloudflare header verification
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
				if err != nil {
					return nil, err
				}
				clientConf := &utls.Config{
					ServerName: testHost,
				}
				tlsConn := utls.UClient(rawConn, clientConf, utls.HelloChrome_Auto)
				if err := tlsConn.Handshake(); err != nil {
					rawConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", testHost), nil)
	if err != nil {
		return CdnScanResult{
			IP:        ip,
			Alive:     true,
			LatencyMs: latency,
		}
	}
	req.Host = testHost
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return CdnScanResult{
			IP:        ip,
			Alive:     true,
			LatencyMs: latency,
			Error:     "http verification failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	return CdnScanResult{
		IP:        ip,
		Alive:     true,
		LatencyMs: latency,
		HTTPCode:  resp.StatusCode,
	}
}
