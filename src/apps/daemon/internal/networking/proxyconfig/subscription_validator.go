package proxyconfig

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// TestEndpoint defines a target server for multi-operator proxy health validation.
type TestEndpoint struct {
	Host             string
	Path             string
	ExpectedStatuses []int
}

// DefaultTestEndpoints provides 3 independent operator endpoints for health checks.
var DefaultTestEndpoints = []TestEndpoint{
	{
		Host:             "cp.cloudflare.com",
		Path:             "/generate_204",
		ExpectedStatuses: []int{204},
	},
	{
		Host:             "www.gstatic.com",
		Path:             "/generate_204",
		ExpectedStatuses: []int{204},
	},
	{
		Host:             "captive.apple.com",
		Path:             "/hotspot-detect.html",
		ExpectedStatuses: []int{200},
	},
}

// ReserveLoopbackPorts binds `count` ephemeral TCP sockets on 127.0.0.1 to obtain
// guaranteed non-colliding loopback ports, then closes them for immediate daemon binding.
func ReserveLoopbackPorts(count int, maxAttempts int) ([]int, error) {
	if count <= 0 {
		return nil, nil
	}
	if maxAttempts <= 0 {
		maxAttempts = 3
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		listeners := make([]net.Listener, 0, count)
		ports := make([]int, 0, count)
		seen := make(map[int]bool)
		failed := false

		for i := 0; i < count; i++ {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				failed = true
				break
			}
			listeners = append(listeners, ln)
			p := ln.Addr().(*net.TCPAddr).Port
			if seen[p] {
				failed = true
				break
			}
			seen[p] = true
			ports = append(ports, p)
		}

		// Always release all listeners before evaluating or returning
		for _, ln := range listeners {
			_ = ln.Close()
		}

		if !failed && len(ports) == count {
			return ports, nil
		}
	}

	return nil, fmt.Errorf("failed to reserve %d unique loopback ports after %d attempts", count, maxAttempts)
}

// IsPermanentHTTPError returns true if an HTTP status indicates a non-retryable client error.
// 408 (Request Timeout) and 429 (Too Many Requests) are excluded since they are transient.
func IsPermanentHTTPError(statusCode int) bool {
	if statusCode >= 400 && statusCode < 500 {
		if statusCode == 408 || statusCode == 429 {
			return false
		}
		return true
	}
	return false
}

// QuorumEvaluation holds the result of a multi-round health check.
type QuorumEvaluation struct {
	Survivors       []string
	MedianLatencies map[string]time.Duration
	FlakyPercent    float64
	TotalEvaluated  int
	PassedEver      int
}

// EvaluateQuorum filters proxy candidates requiring successful passes across ALL rounds.
// Candidates passing only a subset of rounds are classified as flaky and rejected.
func EvaluateQuorum(roundResults []map[string]time.Duration) QuorumEvaluation {
	if len(roundResults) == 0 {
		return QuorumEvaluation{
			MedianLatencies: make(map[string]time.Duration),
		}
	}

	allCandidates := make(map[string]bool)
	candidateLatencies := make(map[string][]time.Duration)

	for _, round := range roundResults {
		for candidate, lat := range round {
			allCandidates[candidate] = true
			candidateLatencies[candidate] = append(candidateLatencies[candidate], lat)
		}
	}

	requiredRounds := len(roundResults)
	var survivors []string
	medianLatencies := make(map[string]time.Duration)
	passedEver := len(allCandidates)

	for candidate, latencies := range candidateLatencies {
		if len(latencies) == requiredRounds {
			survivors = append(survivors, candidate)

			// Calculate median latency
			sort.Slice(latencies, func(i, j int) bool {
				return latencies[i] < latencies[j]
			})
			median := latencies[len(latencies)/2]
			medianLatencies[candidate] = median
		}
	}

	// Sort survivors by median latency (fastest first)
	sort.Slice(survivors, func(i, j int) bool {
		latA := medianLatencies[survivors[i]]
		latB := medianLatencies[survivors[j]]
		if latA != latB {
			return latA < latB
		}
		return survivors[i] < survivors[j]
	})

	var flakyPercent float64
	if passedEver > 0 {
		flakyCount := passedEver - len(survivors)
		flakyPercent = (float64(flakyCount) / float64(passedEver)) * 100.0
	}

	return QuorumEvaluation{
		Survivors:       survivors,
		MedianLatencies: medianLatencies,
		FlakyPercent:    flakyPercent,
		TotalEvaluated:  passedEver,
		PassedEver:      passedEver,
	}
}

// BalancedPortCapper trims a slice of proxy configurations to a maximum limit,
// evenly balancing nodes across port buckets (e.g. 443 vs 8080) to avoid port skew.
func BalancedPortCapper(configs []string, extractPort func(string) int, limit int) []string {
	if len(configs) <= limit {
		return configs
	}

	buckets := make(map[int][]string)
	for _, cfg := range configs {
		port := extractPort(cfg)
		buckets[port] = append(buckets[port], cfg)
	}

	var ports []int
	for p := range buckets {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	var result []string
	idx := 0
	for len(result) < limit {
		progressed := false
		for _, p := range ports {
			bucket := buckets[p]
			if idx < len(bucket) {
				result = append(result, bucket[idx])
				progressed = true
				if len(result) == limit {
					break
				}
			}
		}
		if !progressed {
			break
		}
		idx++
	}

	return result
}

// ParsePortFromShareLink extracts the destination port from a share link URI.
func ParsePortFromShareLink(link string) int {
	if !strings.Contains(link, "://") {
		return 0
	}
	parts := strings.SplitN(link, "://", 2)
	rest := parts[1]
	if idx := strings.Index(rest, "#"); idx != -1 {
		rest = rest[:idx]
	}
	if idx := strings.Index(rest, "?"); idx != -1 {
		rest = rest[:idx]
	}
	if idx := strings.LastIndex(rest, "@"); idx != -1 {
		rest = rest[idx+1:]
	}
	// Bracketed IPv6 handling
	if strings.HasPrefix(rest, "[") {
		if idx := strings.Index(rest, "]"); idx != -1 {
			rest = rest[idx+1:]
			if strings.HasPrefix(rest, ":") {
				rest = rest[1:]
			}
		}
	} else if idx := strings.LastIndex(rest, ":"); idx != -1 {
		rest = rest[idx+1:]
	} else {
		return 0
	}

	var port int
	_, _ = fmt.Sscanf(rest, "%d", &port)
	return port
}
