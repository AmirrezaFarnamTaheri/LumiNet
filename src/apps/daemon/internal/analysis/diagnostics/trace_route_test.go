package diagnostics

import (
	"math"
	"testing"
)

func TestParseTraceRouteOutputPreservesLossJitterAndLoadBalancing(t *testing.T) {
	output := `traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
 1  192.0.2.1  1.000 ms  1.500 ms  2.000 ms
 2  198.51.100.1  10.000 ms  198.51.100.2  12.000 ms  *
 3  93.184.216.34  20.000 ms  22.000 ms  21.000 ms
`
	hops, destination, reached := parseTraceRouteOutput(output, "example.com", 3)
	if destination != "93.184.216.34" || !reached || len(hops) != 3 {
		t.Fatalf("destination=%q reached=%v hops=%#v", destination, reached, hops)
	}
	if !hops[1].LoadBalanced || hops[1].Timeouts != 1 || len(hops[1].Addresses) != 2 {
		t.Fatalf("load-balanced hop not preserved: %#v", hops[1])
	}
	if math.Abs(hops[1].LossPercent-(100.0/3.0)) > 0.001 {
		t.Fatalf("loss=%f, want 33.333", hops[1].LossPercent)
	}
	if math.Abs(hops[2].JitterMs-1.5) > 0.001 {
		t.Fatalf("jitter=%f, want 1.5", hops[2].JitterMs)
	}
	if !hops[2].Reached {
		t.Fatalf("destination hop was not marked reached: %#v", hops[2])
	}
}

func TestParseTraceRouteOutputHandlesWindowsTimeouts(t *testing.T) {
	output := `Tracing route to example.com [93.184.216.34]
  1    <1 ms     1 ms     2 ms  192.0.2.1
  2     *        *        *     Request timed out.
  3    20 ms    21 ms    22 ms  93.184.216.34
`
	hops, destination, reached := parseTraceRouteOutput(output, "example.com", 3)
	if destination != "93.184.216.34" || !reached || len(hops) != 3 {
		t.Fatalf("destination=%q reached=%v hops=%#v", destination, reached, hops)
	}
	if hops[1].Timeouts != 3 || hops[1].LossPercent != 100 {
		t.Fatalf("timeout hop=%#v", hops[1])
	}
}

func TestNormalizeTraceTargetRejectsOptionLikeAndPathTargets(t *testing.T) {
	for _, target := range []string{"", "-m", "example.com/path", "example .com", "https://example.com"} {
		if got, err := normalizeTraceTarget(target); err == nil {
			t.Fatalf("unsafe target %q normalized to %q", target, got)
		}
	}
	for _, target := range []string{"example.com", "example.com:443", "1.1.1.1", "[2001:4860:4860::8888]"} {
		if _, err := normalizeTraceTarget(target); err != nil {
			t.Fatalf("valid target %q rejected: %v", target, err)
		}
	}
}

func TestBoundedTraceOptionRejectsOversizedValues(t *testing.T) {
	if _, err := boundedTraceOption(map[string]string{"max_hops": "65"}, "max_hops", defaultTraceMaxHops, 1, maxTraceMaxHops); err == nil {
		t.Fatal("oversized max_hops accepted")
	}
	if got, err := boundedTraceOption(nil, "max_hops", defaultTraceMaxHops, 1, maxTraceMaxHops); err != nil || got != defaultTraceMaxHops {
		t.Fatalf("default max_hops=%d err=%v", got, err)
	}
}
