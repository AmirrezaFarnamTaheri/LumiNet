// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Cloudflare-vless-trojan-main
// Target path: server/internal/proxy/cf_vless_socket.go

package proxy

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"sort"
	"sync"
	"time"
)

// CFVLESSSocket manages the Workers VLESS socket implementation, bridging network streams.
type CFVLESSSocket struct {
	mu          sync.RWMutex
	concurrency int
	timeout     time.Duration
	results     []IPTestResult
}

// NewCFVLESSSocket instantiates a CFVLESSSocket.
func NewCFVLESSSocket() *CFVLESSSocket {
	return &CFVLESSSocket{
		concurrency: 10,
		timeout:     1 * time.Second,
		results:     make([]IPTestResult, 0),
	}
}

// IPTestResult holds benchmark latency results.
type IPTestResult struct {
	IP      string        `json:"ip"`
	Latency time.Duration `json:"latency"`
	Success bool          `json:"success"`
}

// 1. ScanCleanIPs benchmarks Cloudflare IP addresses concurrently and returns the best IP.
func (c *CFVLESSSocket) ScanCleanIPs(ctx context.Context, ipAddresses []string, port string) (string, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	bestIP := ""
	bestLatency := 999 * time.Second

	c.mu.RLock()
	conLimit := c.concurrency
	dialTimeout := c.timeout
	c.mu.RUnlock()

	limit := make(chan struct{}, conLimit)

	for _, ip := range ipAddresses {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			select {
			case limit <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-limit }()

			start := time.Now()
			dialer := net.Dialer{Timeout: dialTimeout}
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(targetIP, port))
			elapsed := time.Since(start)

			res := IPTestResult{IP: targetIP, Latency: elapsed, Success: err == nil}
			c.mu.Lock()
			c.results = append(c.results, res)
			c.mu.Unlock()

			if err == nil {
				conn.Close()
				mu.Lock()
				if elapsed < bestLatency {
					bestLatency = elapsed
					bestIP = targetIP
				}
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()

	if bestIP == "" {
		return "", net.ErrWriteToConnected
	}
	return bestIP, nil
}

// 2. BridgeSockets pipes bidirectional traffic between client WebSocket connection and target server.
func (c *CFVLESSSocket) BridgeSockets(ctx context.Context, wsConn io.ReadWriter, targetAddr string) error {
	c.mu.RLock()
	dialTimeout := c.timeout
	c.mu.RUnlock()

	dialer := net.Dialer{Timeout: dialTimeout}
	serverConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return err
	}
	defer serverConn.Close()

	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(serverConn, wsConn)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(wsConn, serverConn)
		errChan <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}

// 3. SetConcurrencyLimit configures max concurrent scanners.
func (c *CFVLESSSocket) SetConcurrencyLimit(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.concurrency = n
}

// 4. SetTimeout configures TCP connection boundaries.
func (c *CFVLESSSocket) SetTimeout(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = d
}

// 5. GetTimeout returns TCP connection boundaries.
func (c *CFVLESSSocket) GetTimeout() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.timeout
}

// 6. BenchmarkIPAddress benchmarks a single IP address.
func (c *CFVLESSSocket) BenchmarkIPAddress(ctx context.Context, ip string, port string) (time.Duration, error) {
	start := time.Now()
	dialer := net.Dialer{Timeout: c.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

// 7. ResolveHostAddress translates server hosts to IP addresses.
func (c *CFVLESSSocket) ResolveHostAddress(ctx context.Context, host string) ([]string, error) {
	resolver := &net.Resolver{}
	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// 8. CloseSockets is a placeholder interface method.
func (c *CFVLESSSocket) CloseSockets() {
	// Diagnostic stub
}

// 9. GetScannedResults returns recorded scan latency values.
func (c *CFVLESSSocket) GetScannedResults() []IPTestResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]IPTestResult, len(c.results))
	copy(copied, c.results)
	return copied
}

// 10. AddScannedResult adds a scan result to results list.
func (c *CFVLESSSocket) AddScannedResult(res IPTestResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = append(c.results, res)
}

// 11. ClearScannedResults clears scanned results lists.
func (c *CFVLESSSocket) ClearScannedResults() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = make([]IPTestResult, 0)
}

// 12. ExportScannedResultsJSON exports results lists to JSON configurations.
func (c *CFVLESSSocket) ExportScannedResultsJSON(filePath string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, err := json.MarshalIndent(c.results, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 13. ImportScannedResultsJSON imports results lists from JSON configurations.
func (c *CFVLESSSocket) ImportScannedResultsJSON(filePath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	var res []IPTestResult
	if err := json.Unmarshal(data, &res); err != nil {
		return err
	}
	c.results = res
	return nil
}

// 14. SortScannedResults sorts scanned results by lowest latency.
func (c *CFVLESSSocket) SortScannedResults() {
	c.mu.Lock()
	defer c.mu.Unlock()
	sort.Slice(c.results, func(i, j int) bool {
		return c.results[i].Latency < c.results[j].Latency
	})
}

// 15. RemoveFailedResults filters failed scan results.
func (c *CFVLESSSocket) RemoveFailedResults() {
	c.mu.Lock()
	defer c.mu.Unlock()
	filtered := make([]IPTestResult, 0)
	for _, r := range c.results {
		if r.Success {
			filtered = append(filtered, r)
		}
	}
	c.results = filtered
}
