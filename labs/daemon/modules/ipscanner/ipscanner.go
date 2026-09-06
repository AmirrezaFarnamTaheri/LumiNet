// Package ipscanner provides concurrent IP scanning with latency testing.
// Ported from SIMORGH's PingEngine and RKh-CF-Scanner's test_ip.
//
// Features:
// - Concurrent TCP port probing
// - TLS handshake latency measurement
// - Download speed testing
// - Weighted scoring (latency + stability + speed)
// - CIDR expansion with sampling
package ipscanner

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maybeknott/luminet/internal/scan"
)

// ScanResult holds the result of scanning a single IP.
type ScanResult struct {
	IP         string        `json:"ip"`
	Port       int           `json:"port"`
	Latency    time.Duration `json:"latency"`
	TCPSuccess bool          `json:"tcpSuccess"`
	TLSSuccess bool          `json:"tlsSuccess"`
	SpeedMbps  float64       `json:"speedMbps"`
	Score      float64       `json:"score"`
	Error      string        `json:"error,omitempty"`
}

// ScanConfig holds scanner configuration.
type ScanConfig struct {
	// Target IPs to scan.
	IPs []string
	// Port to probe.
	Port int
	// SNI for TLS handshake.
	SNI string
	// Number of concurrent workers.
	Concurrency int
	// TCP connection timeout.
	TCPTimeout time.Duration
	// TLS handshake timeout.
	TLSTimeout time.Duration
	// Number of latency samples per IP.
	LatencySamples int
	// Whether to run speed test.
	SpeedTest bool
	// AllowInsecureTLS permits TLS probes against endpoints whose certificates
	// cannot be verified. It is disabled by default and should only be used for
	// explicit observation workflows.
	AllowInsecureTLS bool
	// EnableUDPNoise sends a synthetic UDP packet before TCP probing. It is
	// disabled by default because scanning must not alter target traffic unless
	// the caller explicitly requests that behavior.
	EnableUDPNoise bool
	// Speed test URL.
	SpeedTestURL string
	// Speed test duration.
	SpeedTestDuration time.Duration
	// Scoring weights
	LatencyWeight   float64
	StabilityWeight float64
	SpeedWeight     float64
}

// DefaultScanConfig returns a default scan configuration.
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		Port:              443,
		Concurrency:       50,
		TCPTimeout:        2 * time.Second,
		TLSTimeout:        5 * time.Second,
		LatencySamples:    3,
		SpeedTest:         false,
		SpeedTestURL:      "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
		SpeedTestDuration: 5 * time.Second,
		LatencyWeight:     0.45,
		StabilityWeight:   0.25,
		SpeedWeight:       0.30,
	}
}

// Scanner performs concurrent IP scanning.
type Scanner struct {
	config     ScanConfig
	results    []ScanResult
	mu         sync.Mutex
	scanned    atomic.Int64
	total      int
	onProgress func(scanned, total int)
}

// NewScanner creates a new IP scanner.
func NewScanner(config ScanConfig) *Scanner {
	return &Scanner{
		config: config,
	}
}

// SetProgressCallback sets the progress callback function.
func (s *Scanner) SetProgressCallback(fn func(scanned, total int)) {
	s.onProgress = fn
}

// Scan performs concurrent scanning of all configured IPs.
func (s *Scanner) Scan(ctx context.Context) []ScanResult {
	s.total = len(s.config.IPs)
	s.results = make([]ScanResult, 0, s.total)

	// Create worker pool
	ipCh := make(chan string, s.config.Concurrency)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				result := s.scanIP(ctx, ip)
				s.mu.Lock()
				s.results = append(s.results, result)
				s.mu.Unlock()
				s.scanned.Add(1)
				if s.onProgress != nil {
					s.onProgress(int(s.scanned.Load()), s.total)
				}
			}
		}()
	}

	// Send IPs to workers
	dispatchTargets:
	for _, ip := range s.config.IPs {
		select {
		case <-ctx.Done():
			break dispatchTargets
		case ipCh <- ip:
		}
	}
	close(ipCh)
	wg.Wait()

	// Sort by score (descending)
	sort.Slice(s.results, func(i, j int) bool {
		return s.results[i].Score > s.results[j].Score
	})

	return s.results
}

// scanIP scans a single IP address.
func (s *Scanner) scanIP(ctx context.Context, ip string) ScanResult {
	result := ScanResult{
		IP:   ip,
		Port: s.config.Port,
	}

	if s.config.EnableUDPNoise {
		s.udpNoise(ctx, ip, s.config.Port)
	}

	// TCP latency test
	latencies := make([]time.Duration, 0, s.config.LatencySamples)
	for i := 0; i < s.config.LatencySamples; i++ {
		latency, err := s.tcpPing(ctx, ip, s.config.Port)
		if err != nil {
			result.Error = err.Error()
			break
		}
		latencies = append(latencies, latency)
		result.TCPSuccess = true
	}

	if len(latencies) > 0 {
		// Average latency
		var total time.Duration
		for _, l := range latencies {
			total += l
		}
		result.Latency = total / time.Duration(len(latencies))
	}

	// TLS handshake test
	if result.TCPSuccess {
		tlsLatency, err := s.tlsHandshake(ctx, ip, s.config.Port, s.config.SNI)
		if err == nil {
			result.TLSSuccess = true
			result.Latency = tlsLatency
		}
	}

	// Speed test (HTTP/TLS)
	if s.config.SpeedTest && result.TLSSuccess {
		speed, err := s.speedTest(ctx, ip, s.config.Port, s.config.SNI)
		if err == nil {
			result.SpeedMbps = speed
		}
	}

	// Calculate score
	result.Score = s.calculateScore(result)

	return result
}

// tcpPing performs a TCP connect and measures latency.
func targetAddress(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (s *Scanner) tcpPing(ctx context.Context, ip string, port int) (time.Duration, error) {
	addr := targetAddress(ip, port)
	start := time.Now()
	dialer := &net.Dialer{Timeout: s.config.TCPTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

// tlsHandshake performs a TLS handshake and measures latency.
func (s *Scanner) tlsHandshake(ctx context.Context, ip string, port int, sni string) (time.Duration, error) {
	addr := targetAddress(ip, port)

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: s.config.AllowInsecureTLS,
	}

	dialer := &net.Dialer{Timeout: s.config.TLSTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, tlsConfig)
	start := time.Now()
	if err := tlsConn.Handshake(); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// udpNoise sends a random UDP packet to disrupt some basic DPIs before TCP connection.
func (s *Scanner) udpNoise(ctx context.Context, ip string, port int) {
	addr := targetAddress(ip, port)
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	// Generate random 16-64 bytes payload
	payloadSize := 16 + rand.Intn(48)
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(rand.Intn(256))
	}
	conn.Write(payload)
}

// speedTest performs a download speed test through the IP.
func (s *Scanner) speedTest(ctx context.Context, ip string, port int, sni string) (float64, error) {
	addr := targetAddress(ip, port)

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: s.config.AllowInsecureTLS,
	}

	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: s.config.TLSTimeout}
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			return tls.Client(conn, tlsConfig), nil
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   s.config.SpeedTestDuration + 5*time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", s.config.SpeedTestURL, nil)
	if err != nil {
		return 0, err
	}
	req.Host = sni

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// Read response body
	buf := make([]byte, 32*1024)
	var totalBytes int64
	for {
		n, err := resp.Body.Read(buf)
		totalBytes += int64(n)
		if err != nil {
			break
		}
		if time.Since(start) > s.config.SpeedTestDuration {
			break
		}
	}

	elapsed := time.Since(start).Seconds()
	if elapsed == 0 {
		return 0, nil
	}

	// Mbps = (bytes * 8) / (seconds * 1_000_000)
	return float64(totalBytes*8) / (elapsed * 1_000_000), nil
}

// calculateScore computes a weighted score for a scan result.
func (s *Scanner) calculateScore(result ScanResult) float64 {
	if !result.TCPSuccess {
		return 0
	}

	// Latency score (0-100, lower latency = higher score)
	latencyMs := float64(result.Latency.Milliseconds())
	latencyScore := 100.0
	if latencyMs > 0 {
		latencyScore = 100.0 / (1.0 + latencyMs/100.0)
	}

	// Stability score (based on TLS success)
	stabilityScore := 0.0
	if result.TLSSuccess {
		stabilityScore = 100.0
	} else if result.TCPSuccess {
		stabilityScore = 50.0
	}

	// Speed score (0-100, higher = better)
	speedScore := 0.0
	if result.SpeedMbps > 0 {
		speedScore = min(result.SpeedMbps, 100.0)
	}

	return latencyScore*s.config.LatencyWeight +
		stabilityScore*s.config.StabilityWeight +
		speedScore*s.config.SpeedWeight
}

// ExpandCIDR expands a CIDR range into individual IPs.
// Delegates to scan.ExpandCIDRMax for consistency.
func ExpandCIDR(cidr string, maxIPs int) ([]string, error) {
	return scan.ExpandCIDRMax(cidr, maxIPs)
}

// SampleCIDR randomly samples IPs from a CIDR range.
// Delegates to scan.SampleCIDR for consistency.
func SampleCIDR(cidr string, count int) ([]string, error) {
	return scan.SampleCIDR(cidr, count)
}

// SampleSubnetsWeighted performs weighted random IP sampling across multiple CIDR blocks
// based on their host capacities, matching the Cloudflare IP Scanner algorithm.
func SampleSubnetsWeighted(cidrs []string, totalCount int) ([]string, error) {
	if len(cidrs) == 0 || totalCount <= 0 {
		return nil, nil
	}

	type cidrInfo struct {
		cidr  string
		limit *big.Int
	}

	var infos []cidrInfo
	totalLimit := new(big.Int)

	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue // skip invalid CIDRs
		}
		ones, bits := ipnet.Mask.Size()
		limit := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
		infos = append(infos, cidrInfo{cidr: cidr, limit: limit})
		totalLimit.Add(totalLimit, limit)
	}

	if len(infos) == 0 || totalLimit.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("no valid CIDRs provided")
	}

	// Allocate count to each CIDR based on its weight
	var ips []string
	seen := make(map[string]bool)

	// To prevent infinite loops if we ask for more IPs than exist
	maxAttempts := totalCount * 3
	attempts := 0

	for len(ips) < totalCount && attempts < maxAttempts {
		attempts++

		// Select a random subnet index weighted by its capacity
		// Generate random big.Int offset in [0, totalLimit - 1]
		rndVal, err := crand.Int(crand.Reader, totalLimit)
		if err != nil {
			return nil, err
		}

		// Find which subnet this offset corresponds to
		var selectedCIDR string
		accum := new(big.Int)
		for _, info := range infos {
			accum.Add(accum, info.limit)
			if rndVal.Cmp(accum) < 0 {
				selectedCIDR = info.cidr
				break
			}
		}

		if selectedCIDR == "" {
			continue
		}

		// Sample 1 IP from the selected subnet
		sampled, err := scan.SampleCIDR(selectedCIDR, 1)
		if err == nil && len(sampled) > 0 {
			ip := sampled[0]
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}

	return ips, nil
}
