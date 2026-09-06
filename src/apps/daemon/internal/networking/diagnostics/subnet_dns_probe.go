package diagnostics

import (
	"errors"
	"sync"
)

type DnsServerProbeResult struct {
	ServerIP       string  `json:"server_ip"`
	ResponseTimeMs float64 `json:"response_time_ms"`
	IsResponsive   bool    `json:"is_responsive"`
	IsPoisoned     bool    `json:"is_poisoned"`
}

type SubnetDnsScanner struct {
	mu         sync.RWMutex
	servers    map[string]*DnsServerProbeResult
	expectedIP string
}

func NewSubnetDnsScanner(expectedIP string) *SubnetDnsScanner {
	return &SubnetDnsScanner{
		servers:    make(map[string]*DnsServerProbeResult),
		expectedIP: expectedIP,
	}
}

func (s *SubnetDnsScanner) RecordProbe(ip string, rttMs float64, resolvedIP string, hasError bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if hasError {
		s.servers[ip] = &DnsServerProbeResult{
			ServerIP:       ip,
			ResponseTimeMs: 0,
			IsResponsive:   false,
			IsPoisoned:     false,
		}
		return
	}

	poisoned := (resolvedIP != s.expectedIP)
	s.servers[ip] = &DnsServerProbeResult{
		ServerIP:       ip,
		ResponseTimeMs: rttMs,
		IsResponsive:   true,
		IsPoisoned:     poisoned,
	}
}

func (s *SubnetDnsScanner) SelectCleanFastest() (*DnsServerProbeResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var best *DnsServerProbeResult
	minRtt := 1e9

	for _, srv := range s.servers {
		if srv.IsResponsive && !srv.IsPoisoned && srv.ResponseTimeMs < minRtt {
			minRtt = srv.ResponseTimeMs
			best = srv
		}
	}

	if best == nil {
		return nil, errors.New("no clean responsive dns server available")
	}
	return best, nil
}
