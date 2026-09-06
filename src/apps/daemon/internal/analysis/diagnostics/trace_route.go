package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTraceMaxHops      = 30
	maxTraceMaxHops          = 64
	defaultTraceProbesPerHop = 3
	maxTraceProbesPerHop     = 5
	defaultTraceWait         = time.Second
	maxTraceWait             = 5 * time.Second
	maxTraceOutputBytes      = 256 << 10
)

var errTraceOutputLimit = errors.New("traceroute output exceeds bounded diagnostic limit")

type TraceHop struct {
	TTL          int       `json:"ttl"`
	Addresses    []string  `json:"addresses,omitempty"`
	LatenciesMs  []float64 `json:"latencies_ms,omitempty"`
	Timeouts     int       `json:"timeouts"`
	LossPercent  float64   `json:"loss_percent"`
	MinLatencyMs float64   `json:"min_latency_ms,omitempty"`
	AvgLatencyMs float64   `json:"avg_latency_ms,omitempty"`
	MaxLatencyMs float64   `json:"max_latency_ms,omitempty"`
	JitterMs     float64   `json:"jitter_ms,omitempty"`
	LoadBalanced bool      `json:"load_balanced"`
	Reached      bool      `json:"reached"`
}

type traceCommandSpec struct {
	binary           string
	args             []string
	backend          string
	expectedProbeCnt int
}

func runPlatformTraceRoute(ctx context.Context, job *DiagnosticJob, result *DiagnosticResult) (*DiagnosticResult, error) {
	target, err := normalizeTraceTarget(job.Target)
	if err != nil {
		return nil, err
	}
	maxHops, err := boundedTraceOption(job.Options, "max_hops", defaultTraceMaxHops, 1, maxTraceMaxHops)
	if err != nil {
		return nil, err
	}
	probes, err := boundedTraceOption(job.Options, "probes_per_hop", defaultTraceProbesPerHop, 1, maxTraceProbesPerHop)
	if err != nil {
		return nil, err
	}
	waitMS, err := boundedTraceOption(job.Options, "wait_ms", int(defaultTraceWait/time.Millisecond), 100, int(maxTraceWait/time.Millisecond))
	if err != nil {
		return nil, err
	}

	spec, err := buildTraceCommand(runtime.GOOS, target, maxHops, probes, time.Duration(waitMS)*time.Millisecond)
	if err != nil {
		result.Success = false
		result.RawOutput = err.Error()
		result.Metrics["supported"] = false
		result.Metrics["reason"] = err.Error()
		return result, nil
	}

	output, commandErr := runBoundedTraceCommand(ctx, spec)
	if errors.Is(commandErr, context.Canceled) || errors.Is(commandErr, context.DeadlineExceeded) {
		return nil, commandErr
	}
	hops, destination, reached := parseTraceRouteOutput(string(output), target, spec.expectedProbeCnt)
	if commandErr != nil && len(hops) == 0 {
		return nil, fmt.Errorf("run %s traceroute backend: %w", spec.backend, commandErr)
	}

	result.Success = len(hops) > 0
	result.RawOutput = fmt.Sprintf("Traceroute to %s via %s: %d hops (reached=%t)", target, spec.backend, len(hops), reached)
	result.Metrics["supported"] = true
	result.Metrics["backend"] = spec.backend
	result.Metrics["destination"] = destination
	result.Metrics["reached"] = reached
	result.Metrics["max_hops"] = maxHops
	result.Metrics["probes_per_hop"] = spec.expectedProbeCnt
	result.Metrics["hops"] = hops
	result.Metrics["hop_count"] = len(hops)
	if commandErr != nil {
		result.Metrics["backend_error"] = commandErr.Error()
	}
	return result, nil
}

func buildTraceCommand(goos, target string, maxHops, probes int, wait time.Duration) (traceCommandSpec, error) {
	switch goos {
	case "windows":
		binary, err := exec.LookPath("tracert")
		if err != nil {
			return traceCommandSpec{}, fmt.Errorf("traceroute unavailable: tracert executable not found")
		}
		return traceCommandSpec{
			binary:           binary,
			args:             []string{"-d", "-h", strconv.Itoa(maxHops), "-w", strconv.Itoa(int(wait / time.Millisecond)), target},
			backend:          "tracert",
			expectedProbeCnt: 3,
		}, nil
	default:
		binary, err := exec.LookPath("traceroute")
		if err != nil {
			return traceCommandSpec{}, fmt.Errorf("traceroute unavailable: traceroute executable not found")
		}
		waitSeconds := strconv.FormatFloat(wait.Seconds(), 'f', 3, 64)
		return traceCommandSpec{
			binary:           binary,
			args:             []string{"-n", "-q", strconv.Itoa(probes), "-m", strconv.Itoa(maxHops), "-w", waitSeconds, target},
			backend:          "traceroute",
			expectedProbeCnt: probes,
		}, nil
	}
}

type boundedTraceWriter struct {
	buf []byte
	max int
}

func (w *boundedTraceWriter) Write(p []byte) (int, error) {
	if len(w.buf)+len(p) > w.max {
		remaining := w.max - len(w.buf)
		if remaining > 0 {
			w.buf = append(w.buf, p[:remaining]...)
		}
		return remaining, errTraceOutputLimit
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func runBoundedTraceCommand(ctx context.Context, spec traceCommandSpec) ([]byte, error) {
	cmd := exec.CommandContext(ctx, spec.binary, spec.args...)
	writer := &boundedTraceWriter{max: maxTraceOutputBytes}
	cmd.Stdout = writer
	cmd.Stderr = writer
	err := cmd.Run()
	if len(writer.buf) >= maxTraceOutputBytes {
		return writer.buf, errTraceOutputLimit
	}
	return writer.buf, err
}

func boundedTraceOption(options map[string]string, name string, defaultValue, minValue, maxValue int) (int, error) {
	if len(options) == 0 || strings.TrimSpace(options[name]) == "" {
		return defaultValue, nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(options[name]))
	if err != nil || value < minValue || value > maxValue {
		return 0, fmt.Errorf("traceroute option %s must be an integer in %d..%d", name, minValue, maxValue)
	}
	return value, nil
}

func normalizeTraceTarget(raw string) (string, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", errors.New("traceroute target is required")
	}
	// The backend is invoked without a shell, but option/URL-shaped input still
	// must not be reinterpreted as a hostname. In particular, net.SplitHostPort
	// would otherwise parse "https://example.com" as host "https".
	if strings.ContainsAny(target, "/\\?#") {
		return "", fmt.Errorf("invalid traceroute target %q", raw)
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	} else if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		target = strings.TrimSuffix(strings.TrimPrefix(target, "["), "]")
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		return addr.String(), nil
	}
	target = strings.TrimSuffix(strings.ToLower(target), ".")
	if !validTraceHostname(target) {
		return "", fmt.Errorf("invalid traceroute target %q", raw)
	}
	return target, nil
}

func validTraceHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !isTraceAlphaNum(label[0]) || !isTraceAlphaNum(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !isTraceAlphaNum(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isTraceAlphaNum(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

var traceHeaderIP = regexp.MustCompile(`[\[(]([0-9A-Fa-f:.]+)[\])]`)

func parseTraceRouteOutput(output, target string, expectedProbes int) ([]TraceHop, string, bool) {
	destination := target
	if addr, err := netip.ParseAddr(target); err == nil {
		destination = addr.String()
	} else if match := traceHeaderIP.FindStringSubmatch(output); len(match) == 2 {
		if addr, err := netip.ParseAddr(match[1]); err == nil {
			destination = addr.String()
		}
	}
	destinationAddr, _ := netip.ParseAddr(destination)

	var hops []TraceHop
	for _, rawLine := range strings.Split(output, "\n") {
		fields := strings.Fields(rawLine)
		if len(fields) < 2 {
			continue
		}
		ttl, err := strconv.Atoi(strings.TrimSuffix(fields[0], "."))
		if err != nil || ttl < 1 || ttl > maxTraceMaxHops {
			continue
		}
		hop := TraceHop{TTL: ttl}
		seenAddress := map[string]struct{}{}
		for i, field := range fields[1:] {
			if field == "*" {
				hop.Timeouts++
				continue
			}
			clean := strings.Trim(field, "[](),")
			if addr, err := netip.ParseAddr(clean); err == nil {
				canonical := addr.String()
				if _, exists := seenAddress[canonical]; !exists {
					hop.Addresses = append(hop.Addresses, canonical)
					seenAddress[canonical] = struct{}{}
				}
				if destinationAddr.IsValid() && addr == destinationAddr {
					hop.Reached = true
				}
				continue
			}
			absolute := i + 1
			if absolute+1 < len(fields) && strings.EqualFold(fields[absolute+1], "ms") {
				value := strings.TrimPrefix(strings.TrimSuffix(field, "ms"), "<")
				if latency, err := strconv.ParseFloat(value, 64); err == nil && latency >= 0 {
					hop.LatenciesMs = append(hop.LatenciesMs, latency)
				}
			}
		}
		denominator := expectedProbes
		observed := len(hop.LatenciesMs) + hop.Timeouts
		if observed > denominator {
			denominator = observed
		}
		if denominator > 0 {
			hop.LossPercent = float64(hop.Timeouts) / float64(denominator) * 100
		}
		hop.LoadBalanced = len(hop.Addresses) > 1
		if len(hop.LatenciesMs) > 0 {
			values := append([]float64(nil), hop.LatenciesMs...)
			sort.Float64s(values)
			hop.MinLatencyMs = values[0]
			hop.MaxLatencyMs = values[len(values)-1]
			var total float64
			for _, value := range hop.LatenciesMs {
				total += value
			}
			hop.AvgLatencyMs = total / float64(len(hop.LatenciesMs))
			hop.JitterMs = meanAbsoluteFloatDelta(hop.LatenciesMs)
		}
		hops = append(hops, hop)
	}
	for _, hop := range hops {
		if hop.Reached {
			return hops, destination, true
		}
	}
	return hops, destination, false
}

func meanAbsoluteFloatDelta(samples []float64) float64 {
	if len(samples) < 2 {
		return 0
	}
	var total float64
	for i := 1; i < len(samples); i++ {
		delta := samples[i] - samples[i-1]
		if delta < 0 {
			delta = -delta
		}
		total += delta
	}
	return total / float64(len(samples)-1)
}
