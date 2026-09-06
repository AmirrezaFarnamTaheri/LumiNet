// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: MasterHttpRelayVPN-RUST
// Target path: server/internal/proxy/mhrv.go

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

// MHRVClient implements the mhrv-rs Rust proxy client functionality in Go.
type MHRVClient struct {
	mu          sync.RWMutex
	gasEndpoint string
	httpClient  *http.Client
	latencies   []time.Duration
}

// NewMHRVClient initializes the client pointing to a Google Apps Script HTTPS endpoint.
func NewMHRVClient(gasEndpoint string) *MHRVClient {
	return &MHRVClient{
		gasEndpoint: gasEndpoint,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		latencies:   make([]time.Duration, 0),
	}
}

// 1. GetLatencyJitter calculates the latency variance (jitter) over recorded requests.
func (m *MHRVClient) GetLatencyJitter() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.latencies) < 2 {
		return 0
	}

	var sumDiff time.Duration
	for i := 1; i < len(m.latencies); i++ {
		diff := m.latencies[i] - m.latencies[i-1]
		if diff < 0 {
			diff = -diff
		}
		sumDiff += diff
	}

	return sumDiff / time.Duration(len(m.latencies)-1)
}

// 2. RelayTraffic re-routes user traffic via Google Apps Script HTTPS endpoints, tracking connection timings.
func (m *MHRVClient) RelayTraffic(ctx context.Context, targetURL string, payload []byte) ([]byte, error) {
	m.mu.RLock()
	endpoint := m.gasEndpoint
	client := m.httpClient
	m.mu.RUnlock()

	log.Printf("MHRV: Re-routing traffic to %s via GAS endpoint: %s", targetURL, endpoint)

	reqBody := bytes.NewBuffer(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-MHRV-Target", targetURL)
	req.Header.Set("Content-Type", "application/octet-stream")

	var start, connect, dnsDone time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsDone = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			log.Printf("MHRV: DNS Lookup took %v", time.Since(dnsDone))
		},
		ConnectStart: func(_, _ string) {
			connect = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) {
			log.Printf("MHRV: TCP Connection took %v", time.Since(connect))
		},
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	start = time.Now()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("MHRV relay failed: %w", err)
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)
	m.mu.Lock()
	m.latencies = append(m.latencies, elapsed)
	m.mu.Unlock()

	log.Printf("MHRV: Request completed in %v. Current Jitter: %v", elapsed, m.GetLatencyJitter())

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MHRV GAS endpoint returned %d", resp.StatusCode)
	}

	respPayload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.Printf("MHRV: Received %d bytes from %s via GAS", len(respPayload), targetURL)
	return respPayload, nil
}

// 3. SetGASEndpoint configures Google Apps Script target endpoint.
func (m *MHRVClient) SetGASEndpoint(url string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gasEndpoint = url
}

// 4. GetGASEndpoint returns Google Apps Script target endpoint.
func (m *MHRVClient) GetGASEndpoint() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.gasEndpoint
}

// 5. SetHTTPClient configures HTTP clients.
func (m *MHRVClient) SetHTTPClient(client *http.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.httpClient = client
}

// 6. GetHTTPClient returns active client pointers.
func (m *MHRVClient) GetHTTPClient() *http.Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.httpClient
}

// 7. ClearLatencies clears all latency logs.
func (m *MHRVClient) ClearLatencies() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latencies = make([]time.Duration, 0)
}

// 8. GetLatenciesCount returns count of logged latency values.
func (m *MHRVClient) GetLatenciesCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.latencies)
}

// 9. GetAverageLatency calculates average connection latency values.
func (m *MHRVClient) GetAverageLatency() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	n := len(m.latencies)
	if n == 0 {
		return 0
	}

	var sum time.Duration
	for _, val := range m.latencies {
		sum += val
	}
	return sum / time.Duration(n)
}

// 10. GetMinLatency returns absolute minimum latency.
func (m *MHRVClient) GetMinLatency() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.latencies) == 0 {
		return 0
	}

	minVal := m.latencies[0]
	for _, val := range m.latencies {
		if val < minVal {
			minVal = val
		}
	}
	return minVal
}

// 11. GetMaxLatency returns absolute maximum latency.
func (m *MHRVClient) GetMaxLatency() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.latencies) == 0 {
		return 0
	}

	maxVal := m.latencies[0]
	for _, val := range m.latencies {
		if val > maxVal {
			maxVal = val
		}
	}
	return maxVal
}

// 12. ExportLatenciesJSON saves stats data as JSON.
func (m *MHRVClient) ExportLatenciesJSON(filePath string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var floatList []float64
	for _, dur := range m.latencies {
		floatList = append(floatList, dur.Seconds())
	}

	data, err := json.MarshalIndent(floatList, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 13. ImportLatenciesJSON loads stats database from JSON.
func (m *MHRVClient) ImportLatenciesJSON(filePath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var floatList []float64
	if err := json.Unmarshal(data, &floatList); err != nil {
		return err
	}

	m.latencies = make([]time.Duration, len(floatList))
	for idx, val := range floatList {
		m.latencies[idx] = time.Duration(val * float64(time.Second))
	}
	return nil
}

// 14. BenchmarkEndpoint benchmarks the latency of the GAS endpoint.
func (m *MHRVClient) BenchmarkEndpoint(ctx context.Context) (time.Duration, error) {
	m.mu.RLock()
	endpoint := m.gasEndpoint
	client := m.httpClient
	m.mu.RUnlock()

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "HEAD", endpoint, nil)
	if err != nil {
		return 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return time.Since(start), nil
}

// 15. IsEndpointHealthy checks if endpoint responds to HTTP HEAD.
func (m *MHRVClient) IsEndpointHealthy(ctx context.Context) bool {
	dur, err := m.BenchmarkEndpoint(ctx)
	if err != nil || dur == 0 {
		return false
	}
	return true
}
