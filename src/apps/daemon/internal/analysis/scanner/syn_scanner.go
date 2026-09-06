package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// PortStatus defines the state of a scanned port.
type PortStatus string

const (
	PortOpen     PortStatus = "open"
	PortClosed   PortStatus = "closed"
	PortFiltered PortStatus = "filtered"
)

// SynScanResult holds port audit results.
type SynScanResult struct {
	Port    int           `json:"port"`
	Status  PortStatus    `json:"status"`
	Latency time.Duration `json:"latency"`
}

// SynScanner audits target port accessibility.
type SynScanner struct {
	Target  string
	Ports   []int
	Timeout time.Duration
	Workers int
}

// NewSynScanner creates an instance of SynScanner.
func NewSynScanner(target string, ports []int) *SynScanner {
	return &SynScanner{
		Target:  target,
		Ports:   ports,
		Timeout: 1 * time.Second,
		Workers: 50,
	}
}

// Scan sweeps target ports concurrently.
func (s *SynScanner) Scan(ctx context.Context) ([]SynScanResult, error) {
	results := make([]SynScanResult, len(s.Ports))
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.Workers)

	for i, port := range s.Ports {
		wg.Add(1)
		go func(idx int, p int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[idx] = SynScanResult{Port: p, Status: PortFiltered}
				return
			}
			defer func() { <-sem }()

			start := time.Now()
			addr := net.JoinHostPort(s.Target, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, s.Timeout)
			elapsed := time.Since(start)

			if err != nil {
				status := PortFiltered
				if netErr, ok := err.(net.Error); ok && !netErr.Timeout() {
					status = PortClosed
				}
				results[idx] = SynScanResult{
					Port:    p,
					Status:  status,
					Latency: elapsed,
				}
				return
			}
			conn.Close()

			results[idx] = SynScanResult{
				Port:    p,
				Status:  PortOpen,
				Latency: elapsed,
			}
		}(i, port)
	}

	wg.Wait()
	return results, nil
}
