package warp

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSummarizeWarpAttemptsMeasuresLossAndMedianRTT(t *testing.T) {
	addr := netip.MustParseAddrPort("188.114.96.1:2408")
	result := summarizeWarpAttempts(addr, []warpAttempt{
		{rtt: 30 * time.Millisecond},
		{err: errors.New("timeout")},
		{rtt: 10 * time.Millisecond},
		{rtt: 20 * time.Millisecond},
	})

	if !result.Success {
		t.Fatal("partial success should classify endpoint as reachable")
	}
	if result.Attempts != 4 || result.SuccessfulAttempts != 3 {
		t.Fatalf("attempt accounting = %d/%d, want 3/4 successes", result.SuccessfulAttempts, result.Attempts)
	}
	if math.Abs(result.Loss-25) > 0.0001 {
		t.Fatalf("loss = %.4f, want 25", result.Loss)
	}
	if result.RTT != 20*time.Millisecond {
		t.Fatalf("median RTT = %s, want 20ms", result.RTT)
	}
	if result.Jitter != 15*time.Millisecond {
		t.Fatalf("jitter = %s, want 15ms", result.Jitter)
	}
	if result.Error != "" {
		t.Fatalf("successful result should not retain a transient probe error: %q", result.Error)
	}
}

func TestSummarizeWarpAttemptsAllFailures(t *testing.T) {
	addr := netip.MustParseAddrPort("188.114.96.2:2408")
	result := summarizeWarpAttempts(addr, []warpAttempt{
		{err: errors.New("first")},
		{err: errors.New("last")},
	})
	if result.Success || result.SuccessfulAttempts != 0 || result.Loss != 100 {
		t.Fatalf("all-failure summary = %#v", result)
	}
	if !strings.Contains(result.Error, "all 2 attempts failed") || !strings.Contains(result.Error, "last") {
		t.Fatalf("all-failure error = %q", result.Error)
	}
}

func TestWarpScannerRanksLossBeforeLatency(t *testing.T) {
	stable := netip.MustParseAddrPort("188.114.96.10:2408")
	fastButLossy := netip.MustParseAddrPort("188.114.96.11:2408")

	var mu sync.Mutex
	calls := map[netip.AddrPort]int{}
	scanner := NewWarpScanner(WarpScannerOptions{
		ConcurrentScanners:  2,
		AttemptsPerEndpoint: 3,
		AttemptStagger:      time.Nanosecond,
	})
	scanner.probe = func(_ context.Context, addr netip.AddrPort) (time.Duration, error) {
		mu.Lock()
		defer mu.Unlock()
		idx := calls[addr]
		calls[addr] = idx + 1
		if addr == fastButLossy && idx == 1 {
			return 0, errors.New("transient loss")
		}
		if addr == fastButLossy {
			return 5 * time.Millisecond, nil
		}
		return 40 * time.Millisecond, nil
	}

	results := scanner.Scan(context.Background(), []netip.AddrPort{fastButLossy, stable})
	if len(results) != 2 {
		t.Fatalf("results=%d, want 2", len(results))
	}
	if results[0].AddrPort != stable || results[0].Loss != 0 {
		t.Fatalf("stable endpoint should rank first: %#v", results)
	}
	if results[1].AddrPort != fastButLossy || math.Abs(results[1].Loss-100.0/3.0) > 0.001 {
		t.Fatalf("lossy endpoint summary = %#v", results[1])
	}
}

func TestWarpScannerRanksJitterBeforeMedianLatencyWhenLossMatches(t *testing.T) {
	stable := netip.MustParseAddrPort("188.114.96.30:2408")
	fastButVariable := netip.MustParseAddrPort("188.114.96.31:2408")

	var mu sync.Mutex
	calls := map[netip.AddrPort]int{}
	scanner := NewWarpScanner(WarpScannerOptions{ConcurrentScanners: 2, AttemptsPerEndpoint: 3, AttemptStagger: time.Nanosecond})
	scanner.probe = func(_ context.Context, addr netip.AddrPort) (time.Duration, error) {
		mu.Lock()
		defer mu.Unlock()
		idx := calls[addr]
		calls[addr] = idx + 1
		if addr == fastButVariable {
			return []time.Duration{5 * time.Millisecond, 45 * time.Millisecond, 5 * time.Millisecond}[idx], nil
		}
		return []time.Duration{20 * time.Millisecond, 22 * time.Millisecond, 21 * time.Millisecond}[idx], nil
	}

	results := scanner.Scan(context.Background(), []netip.AddrPort{fastButVariable, stable})
	if len(results) != 2 {
		t.Fatalf("results=%d, want 2", len(results))
	}
	if results[0].AddrPort != stable {
		t.Fatalf("stable endpoint should win equal-loss comparison: %#v", results)
	}
	if results[0].Jitter >= results[1].Jitter {
		t.Fatalf("jitter ordering not reflected: stable=%s variable=%s", results[0].Jitter, results[1].Jitter)
	}
}

func TestWarpScannerAttemptDefaultsAndUpperBound(t *testing.T) {
	defaultScanner := NewWarpScanner(WarpScannerOptions{})
	if defaultScanner.opts.AttemptsPerEndpoint != defaultWarpAttempts {
		t.Fatalf("default attempts=%d, want %d", defaultScanner.opts.AttemptsPerEndpoint, defaultWarpAttempts)
	}
	bounded := NewWarpScanner(WarpScannerOptions{AttemptsPerEndpoint: 100})
	if bounded.opts.AttemptsPerEndpoint != maxWarpAttempts {
		t.Fatalf("bounded attempts=%d, want %d", bounded.opts.AttemptsPerEndpoint, maxWarpAttempts)
	}
}

func TestGenerateCandidatesUsesAuthoritativeCorpusAndNoDuplicates(t *testing.T) {
	scanner := NewWarpScanner(WarpScannerOptions{Ipv4Mode: true})
	results := scanner.GenerateCandidates(250)
	if len(results) != 250 {
		t.Fatalf("generated %d candidates, want 250", len(results))
	}

	allowedPorts := make(map[uint16]struct{}, len(defaultWarpTestPorts))
	for _, port := range defaultWarpTestPorts {
		allowedPorts[port] = struct{}{}
	}
	seen := make(map[netip.AddrPort]struct{}, len(results))
	for _, candidate := range results {
		if !candidate.Addr().Is4() {
			t.Fatalf("IPv4-only scanner generated %s", candidate)
		}
		if _, ok := allowedPorts[candidate.Port()]; !ok {
			t.Fatalf("generated unsupported port %d", candidate.Port())
		}
		ip := candidate.Addr().String()
		matched := false
		for _, prefix := range defaultWarpIPv4Prefixes {
			if strings.HasPrefix(ip, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("generated IP outside authoritative corpus: %s", ip)
		}
		if _, duplicate := seen[candidate]; duplicate {
			t.Fatalf("duplicate candidate generated: %s", candidate)
		}
		seen[candidate] = struct{}{}
	}
}

func TestGenerateCandidatesDualStackSplit(t *testing.T) {
	scanner := NewWarpScanner(WarpScannerOptions{Ipv4Mode: true, Ipv6Mode: true})
	results := scanner.GenerateCandidates(21)
	var ipv4, ipv6 int
	for _, candidate := range results {
		if candidate.Addr().Is4() {
			ipv4++
		} else if candidate.Addr().Is6() {
			ipv6++
		}
	}
	if ipv4 != 10 || ipv6 != 11 {
		t.Fatalf("dual-stack split = v4:%d v6:%d, want 10/11", ipv4, ipv6)
	}
}

func TestWarpScannerResourceBounds(t *testing.T) {
	scanner := NewWarpScanner(WarpScannerOptions{
		ConcurrentScanners:  10000,
		ConnectionTimeout:   time.Hour,
		HandshakeTimeout:    time.Hour,
		NoiseCount:          10000,
		AttemptsPerEndpoint: 10000,
	})
	if scanner.opts.ConcurrentScanners != maxWarpConcurrency {
		t.Fatalf("concurrency=%d, want %d", scanner.opts.ConcurrentScanners, maxWarpConcurrency)
	}
	if scanner.opts.ConnectionTimeout != maxWarpNetworkTimeout || scanner.opts.HandshakeTimeout != maxWarpNetworkTimeout {
		t.Fatalf("timeouts were not bounded: connect=%s handshake=%s", scanner.opts.ConnectionTimeout, scanner.opts.HandshakeTimeout)
	}
	if scanner.opts.NoiseCount != MaxWarpNoisePackets {
		t.Fatalf("noise packets=%d, want %d", scanner.opts.NoiseCount, MaxWarpNoisePackets)
	}
	if scanner.opts.AttemptsPerEndpoint != maxWarpAttempts {
		t.Fatalf("attempts=%d, want %d", scanner.opts.AttemptsPerEndpoint, maxWarpAttempts)
	}

	candidates := scanner.GenerateCandidates(maxWarpCandidates + 500)
	if len(candidates) != maxWarpCandidates {
		t.Fatalf("candidate cap=%d, want %d", len(candidates), maxWarpCandidates)
	}
}

func TestStopOnFirstGoodIPsDoesNotTreatLossyEndpointAsGood(t *testing.T) {
	lossy := netip.MustParseAddrPort("188.114.96.20:2408")
	stable := netip.MustParseAddrPort("188.114.96.21:2408")

	var mu sync.Mutex
	calls := map[netip.AddrPort]int{}
	scanner := NewWarpScanner(WarpScannerOptions{
		ConcurrentScanners:  1,
		AttemptsPerEndpoint: 2,
		AttemptStagger:      time.Nanosecond,
		StopOnFirstGoodIPs:  1,
	})
	scanner.probe = func(_ context.Context, addr netip.AddrPort) (time.Duration, error) {
		mu.Lock()
		defer mu.Unlock()
		idx := calls[addr]
		calls[addr] = idx + 1
		if addr == lossy && idx == 0 {
			return 0, errors.New("transient loss")
		}
		return 10 * time.Millisecond, nil
	}

	results := scanner.Scan(context.Background(), []netip.AddrPort{lossy, stable})
	if len(results) != 2 {
		t.Fatalf("lossy endpoint must not trigger early stop; got %d results", len(results))
	}
	if calls[stable] == 0 {
		t.Fatal("stable endpoint was never probed")
	}
}

func TestInjectNoiseRejectsUnboundedCount(t *testing.T) {
	if err := InjectNoise(context.Background(), "127.0.0.1:2408", MaxWarpNoisePackets+1); err == nil {
		t.Fatal("expected oversized noise count to be rejected before network I/O")
	}
	if err := InjectNoise(context.Background(), "not-a-target", 0); err != nil {
		t.Fatalf("zero noise should be a no-op without resolving target: %v", err)
	}
}

func TestValidateScanLimitsRejectsOperatorOversubscription(t *testing.T) {
	tests := []struct {
		name        string
		candidates  int
		concurrency int
		timeout     time.Duration
		attempts    int
		noise       int
	}{
		{name: "candidates", candidates: maxWarpCandidates + 1},
		{name: "concurrency", concurrency: maxWarpConcurrency + 1},
		{name: "timeout", timeout: maxWarpNetworkTimeout + time.Millisecond},
		{name: "attempts", attempts: maxWarpAttempts + 1},
		{name: "noise", noise: MaxWarpNoisePackets + 1},
		{name: "negative", candidates: -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateScanLimits(test.candidates, test.concurrency, test.timeout, test.attempts, test.noise); err == nil {
				t.Fatal("expected invalid operator limits to be rejected")
			}
		})
	}
	if err := ValidateScanLimits(maxWarpCandidates, maxWarpConcurrency, maxWarpNetworkTimeout, maxWarpAttempts, MaxWarpNoisePackets); err != nil {
		t.Fatalf("boundary values should be accepted: %v", err)
	}
}
