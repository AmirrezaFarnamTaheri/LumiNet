package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/netpolicy"
)

const (
	MaxTorBridgeProbeLines   = 64
	maxTorBridgeLineBytes    = 4096
	defaultBridgeProbeWorker = 8
	maxBridgeProbeWorkers    = 32
	defaultBridgeProbeTime   = 4 * time.Second
	minBridgeProbeTime       = 500 * time.Millisecond
	maxBridgeProbeTime       = 10 * time.Second
	bridgeSlowThreshold      = 500 * time.Millisecond
)

type TorBridgeReachability string

const (
	TorBridgeReachable   TorBridgeReachability = "reachable"
	TorBridgeSlow        TorBridgeReachability = "slow"
	TorBridgeFronted     TorBridgeReachability = "fronted"
	TorBridgeUnreachable TorBridgeReachability = "unreachable"
	TorBridgeUnparsed    TorBridgeReachability = "unparsed"
	TorBridgeRefused     TorBridgeReachability = "refused"
)

type TorBridgeProbeResult struct {
	RawLine      string                `json:"raw_line"`
	Transport    string                `json:"transport"`
	TargetHost   string                `json:"target_host,omitempty"`
	TargetPort   int                   `json:"target_port,omitempty"`
	LatencyMs    int64                 `json:"latency_ms,omitempty"`
	Reachability TorBridgeReachability `json:"reachability"`
	Fronted      bool                  `json:"fronted"`
	Detail       string                `json:"detail,omitempty"`
}

type torBridgeProbeTarget struct {
	Transport string
	Host      string
	Port      int
	Fronted   bool
}

var knownTorBridgeTransports = map[string]struct{}{
	"obfs4": {}, "webtunnel": {}, "snowflake": {}, "meek": {}, "meek_lite": {}, "meek-azure": {},
	"conjure": {}, "scramblesuit": {}, "obfs3": {}, "obfs2": {}, "vanilla": {}, "dnstt": {},
}

var frontedTorBridgeTransports = map[string]struct{}{
	"webtunnel": {}, "snowflake": {}, "meek": {}, "meek_lite": {}, "meek-azure": {}, "conjure": {}, "dnstt": {},
}

// PlanTorBridgeProbe interprets a Tor bridge line without performing network
// I/O. Fronted transports use their URL/front/DoH/DoT endpoint instead of the
// bridge-line address, which is often an RFC documentation placeholder.
func PlanTorBridgeProbe(line string) (torBridgeProbeTarget, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || len(line) > maxTorBridgeLineBytes || strings.ContainsAny(line, "\r\n\x00") {
		return torBridgeProbeTarget{}, errors.New("invalid or empty bridge line")
	}
	if strings.HasPrefix(strings.ToLower(line), "bridge ") {
		line = strings.TrimSpace(line[len("Bridge "):])
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return torBridgeProbeTarget{}, errors.New("empty bridge line")
	}

	transport := "vanilla"
	if _, ok := knownTorBridgeTransports[strings.ToLower(fields[0])]; ok {
		transport = strings.ToLower(fields[0])
	}
	host, port, hasEndpoint := bridgeLineEndpoint(fields, transport)
	_, isFronted := frontedTorBridgeTransports[transport]
	if parsed, err := netip.ParseAddr(host); err == nil && netpolicy.IsDocumentationAddress(parsed) {
		isFronted = true
	}
	if isFronted {
		frontHost, frontPort, err := extractTorBridgeFront(line)
		if err != nil {
			return torBridgeProbeTarget{Transport: transport, Fronted: true}, err
		}
		return torBridgeProbeTarget{Transport: transport, Host: frontHost, Port: frontPort, Fronted: true}, nil
	}
	if !hasEndpoint {
		return torBridgeProbeTarget{Transport: transport}, errors.New("bridge line has no host:port endpoint")
	}
	return torBridgeProbeTarget{Transport: transport, Host: host, Port: port}, nil
}

func bridgeLineEndpoint(fields []string, transport string) (string, int, bool) {
	start := 0
	if len(fields) > 0 {
		if _, ok := knownTorBridgeTransports[strings.ToLower(fields[0])]; ok {
			start = 1
		}
	}
	for _, token := range fields[start:] {
		if strings.Contains(token, "=") {
			continue
		}
		host, port, err := splitBridgeHostPort(token)
		if err == nil {
			return host, port, true
		}
	}
	return "", 0, false
}

func splitBridgeHostPort(token string) (string, int, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", 0, errors.New("empty endpoint")
	}
	host, portText, err := net.SplitHostPort(token)
	if err != nil {
		// net.SplitHostPort requires brackets for IPv6, which is desirable for
		// unambiguous bridge-line parsing. For IPv4/hostname forms it works as-is.
		return "", 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strings.TrimSpace(host) == "" {
		return "", 0, errors.New("invalid bridge endpoint")
	}
	return strings.Trim(host, "[]"), port, nil
}

func extractTorBridgeFront(line string) (string, int, error) {
	if raw := bridgeParameter(line, "url"); raw != "" {
		return parseFrontURL(raw)
	}
	if raw := bridgeParameter(line, "doh"); raw != "" {
		return parseFrontURL(raw)
	}
	if raw := bridgeParameter(line, "dot"); raw != "" {
		if host, port, err := splitBridgeHostPort(raw); err == nil {
			return host, port, nil
		}
		if strings.TrimSpace(raw) != "" && !strings.ContainsAny(raw, "/?#@") {
			return raw, 853, nil
		}
	}
	if raw := bridgeParameter(line, "fronts"); raw != "" {
		if first := strings.TrimSpace(strings.Split(raw, ",")[0]); first != "" {
			return normalizeFrontHost(first, 443)
		}
	}
	if raw := bridgeParameter(line, "front"); raw != "" {
		return normalizeFrontHost(raw, 443)
	}
	return "", 0, errors.New("fronted bridge has no broker/front endpoint")
}

func bridgeParameter(line, key string) string {
	prefix := strings.ToLower(key) + "="
	for _, field := range strings.Fields(line) {
		lower := strings.ToLower(field)
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(field[len(prefix):])
		}
	}
	return ""
}

func parseFrontURL(raw string) (string, int, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", 0, errors.New("invalid front URL")
	}
	port := 443
	if u.Scheme == "http" {
		port = 80
	}
	if explicit := u.Port(); explicit != "" {
		parsed, err := strconv.Atoi(explicit)
		if err != nil || parsed < 1 || parsed > 65535 {
			return "", 0, errors.New("invalid front URL port")
		}
		port = parsed
	}
	return u.Hostname(), port, nil
}

func normalizeFrontHost(raw string, defaultPort int) (string, int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "/?#@") {
		return "", 0, errors.New("invalid front host")
	}
	if host, port, err := splitBridgeHostPort(raw); err == nil {
		return host, port, nil
	}
	if strings.Contains(raw, ":") {
		if addr, err := netip.ParseAddr(raw); err != nil || !addr.Is6() {
			return "", 0, errors.New("invalid front host")
		}
	}
	return strings.Trim(raw, "[]"), defaultPort, nil
}

// ProbeTorBridges performs bounded, read-only TCP reachability checks. Every
// DNS answer must be public before any connection is attempted; mixed
// public/private answers are refused to prevent DNS rebinding and remote-list
// SSRF/port-scan behavior.
func ProbeTorBridges(ctx context.Context, lines []string, workers int, timeout time.Duration) ([]TorBridgeProbeResult, error) {
	return probeTorBridgesWith(ctx, lines, workers, timeout, net.DefaultResolver.LookupNetIP, (&net.Dialer{}).DialContext)
}

type bridgeLookup func(context.Context, string, string) ([]netip.Addr, error)
type bridgeDial func(context.Context, string, string) (net.Conn, error)

func probeTorBridgesWith(ctx context.Context, lines []string, workers int, timeout time.Duration, lookup bridgeLookup, dial bridgeDial) ([]TorBridgeProbeResult, error) {
	if len(lines) > MaxTorBridgeProbeLines {
		return nil, fmt.Errorf("too many bridge lines: %d > %d", len(lines), MaxTorBridgeProbeLines)
	}
	if lookup == nil || dial == nil {
		return nil, errors.New("bridge probe dependencies are required")
	}
	if workers <= 0 {
		workers = defaultBridgeProbeWorker
	}
	if workers > maxBridgeProbeWorkers {
		workers = maxBridgeProbeWorkers
	}
	if timeout <= 0 {
		timeout = defaultBridgeProbeTime
	}
	if timeout < minBridgeProbeTime {
		timeout = minBridgeProbeTime
	}
	if timeout > maxBridgeProbeTime {
		timeout = maxBridgeProbeTime
	}

	type work struct{ index int }
	jobs := make(chan work)
	results := make([]TorBridgeProbeResult, len(lines))
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for job := range jobs {
				results[job.index] = probeOneTorBridge(ctx, lines[job.index], timeout, lookup, dial)
			}
		}()
	}
	for i := range lines {
		select {
		case jobs <- work{index: i}:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	return results, nil
}

func probeOneTorBridge(parent context.Context, line string, timeout time.Duration, lookup bridgeLookup, dial bridgeDial) TorBridgeProbeResult {
	plan, err := PlanTorBridgeProbe(line)
	result := TorBridgeProbeResult{RawLine: strings.TrimSpace(line), Transport: plan.Transport, TargetHost: plan.Host, TargetPort: plan.Port, Fronted: plan.Fronted}
	if err != nil {
		result.Reachability = TorBridgeUnparsed
		result.Detail = err.Error()
		return result
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	addresses, err := resolvePublicBridgeTarget(ctx, plan.Host, lookup)
	if err != nil {
		result.Reachability = TorBridgeRefused
		result.Detail = err.Error()
		return result
	}

	start := time.Now()
	var lastErr error
	for _, address := range addresses {
		conn, err := dial(ctx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(plan.Port)))
		if err != nil {
			lastErr = err
			continue
		}
		_ = conn.Close()
		result.LatencyMs = time.Since(start).Milliseconds()
		if plan.Fronted {
			result.Reachability = TorBridgeFronted
		} else if time.Duration(result.LatencyMs)*time.Millisecond >= bridgeSlowThreshold {
			result.Reachability = TorBridgeSlow
		} else {
			result.Reachability = TorBridgeReachable
		}
		result.Detail = fmt.Sprintf("%d ms", result.LatencyMs)
		return result
	}
	result.Reachability = TorBridgeUnreachable
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.Detail = "timed out"
	} else if lastErr != nil {
		result.Detail = lastErr.Error()
	} else {
		result.Detail = "unreachable"
	}
	return result
}

func resolvePublicBridgeTarget(ctx context.Context, host string, lookup bridgeLookup) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		literal = literal.Unmap()
		if !netpolicy.IsPublicAddress(literal) {
			return nil, fmt.Errorf("non-public probe target refused: %s", literal)
		}
		return []netip.Addr{literal}, nil
	}
	addresses, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve probe target %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve probe target %q: no addresses", host)
	}
	unique := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !netpolicy.IsPublicAddress(address) {
			return nil, fmt.Errorf("non-public DNS answer refused for %q: %s", host, address)
		}
		unique[address] = struct{}{}
	}
	out := make([]netip.Addr, 0, len(unique))
	for address := range unique {
		out = append(out, address)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out, nil
}
