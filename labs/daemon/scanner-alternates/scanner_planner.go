package scanner

// scanner_planner.go — ScanTargetPlanner: full CIDR/range/IPv6 expansion,
// port parsing, token validation, target classification, preview plan counting.
// Source: MaybeScanner/ScanTargetPlanner.java (exhaustive, every method)

import (
	"math/big"
	"net"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Token classification helpers
// Source: MaybeScanner/ScanTargetPlanner.java
// ---------------------------------------------------------------------------

// IsIPv4 returns true if value is a valid dotted-decimal IPv4 address.
// Source: ScanTargetPlanner.java isIpv4()
func IsIPv4(value string) bool {
	value = strings.TrimSpace(value)
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
		// Reject leading zeros (e.g. "01")
		if strconv.Itoa(n) != p {
			return false
		}
	}
	return true
}

// IsIPAddress returns true if value is a valid IPv4 or IPv6 address.
// Source: ScanTargetPlanner.java isIp()
func IsIPAddress(value string) bool {
	value = strings.TrimSpace(value)
	if IsIPv4(value) {
		return true
	}
	if !strings.Contains(value, ":") {
		return false
	}
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() == nil // must be IPv6
}

// LooksLikeCIDR returns true if value contains a "/" prefix.
// Source: ScanTargetPlanner.java looksLikePrefix()
func LooksLikeCIDR(value string) bool {
	return value != "" && strings.Contains(strings.TrimSpace(value), "/")
}

// LooksLikeIPv4Range returns true if value is "A.B.C.D-E.F.G.H".
// Source: ScanTargetPlanner.java looksLikeIpv4Range()
func LooksLikeIPv4Range(value string) bool {
	value = strings.TrimSpace(value)
	parts := strings.SplitN(value, "-", 2)
	return len(parts) == 2 && IsIPv4(parts[0]) && IsIPv4(parts[1])
}

// CleanTargetToken strips surrounding quotes, brackets, commas, and whitespace from a token.
// Source: ScanTargetPlanner.java cleanToken()
func CleanTargetToken(value string) string {
	r := strings.TrimSpace(value)
	r = strings.ReplaceAll(r, `"`, "")
	r = strings.ReplaceAll(r, ",", "")
	r = strings.ReplaceAll(r, "[", "")
	r = strings.ReplaceAll(r, "]", "")
	return r
}

// ParsePorts parses a comma/semicolon/whitespace separated list of port numbers.
// Always returns at least [443] if no valid ports found.
// Source: ScanTargetPlanner.java parsePorts()
func ParsePorts(value string) []int {
	seen := make(map[int]bool)
	var out []int
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	}) {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && n > 0 && n < 65536 && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return []int{443}
	}
	return out
}

// UniqueTokens splits a multi-token string on common delimiters, cleans each token,
// and returns deduplicated non-empty values preserving insertion order.
// Source: ScanTargetPlanner.java lines() + unique()
func UniqueTokens(value string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	}) {
		clean := CleanTargetToken(part)
		if clean != "" && !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// CIDR and range expansion
// Source: MaybeScanner/ScanTargetPlanner.java expandCidr(), expandRange(),
//         expandIpv6Cidr(), expandTargetsDetailed()
// ---------------------------------------------------------------------------

// ExpandedTarget is a single IP produced from a CIDR/range expansion.
type ExpandedTarget struct {
	Address   string
	Expansion *TargetExpansionMeta // nil for plain IP/hostname tokens
}

// ExpandTargetsDetailed expands a list of tokens (IPs, CIDRs, ranges, hostnames)
// into individual ExpandedTargets, capped at totalCap (0 = unlimited).
// Source: ScanTargetPlanner.java expandTargetsDetailed()
func ExpandTargetsDetailed(raw []string, totalCap int) []ExpandedTarget {
	var out []ExpandedTarget
	cap := totalCap
	if cap <= 0 {
		cap = int(^uint(0) >> 1) // max int
	}
	for _, value := range raw {
		if len(out) >= cap {
			break
		}
		clean := CleanTargetToken(value)
		if clean == "" {
			continue
		}
		remaining := cap - len(out)
		if LooksLikeCIDR(clean) {
			members := expandCIDR(clean, remaining)
			theoretical := EstimateCIDRCount(clean, int(^uint(0)>>1))
			appendExpanded(&out, clean, members, theoretical)
		} else if LooksLikeIPv4Range(clean) {
			members := expandIPv4Range(clean, remaining)
			theoretical := EstimateRangeCount(clean, int(^uint(0)>>1))
			appendExpanded(&out, clean, members, theoretical)
		} else {
			out = append(out, ExpandedTarget{Address: clean, Expansion: nil})
		}
	}
	return out
}

func appendExpanded(out *[]ExpandedTarget, parent string, members []string, theoretical int) {
	capped := len(members)
	for i, addr := range members {
		meta := NewExpansionMeta(parent, i, theoretical, capped)
		*out = append(*out, ExpandedTarget{Address: addr, Expansion: &meta})
	}
}

// expandIPv4Range enumerates all IPs in "A.B.C.D-E.F.G.H" up to cap.
// Source: ScanTargetPlanner.java expandRange()
func expandIPv4Range(rangeStr string, cap int) []string {
	var out []string
	parts := strings.SplitN(rangeStr, "-", 2)
	if len(parts) != 2 || !IsIPv4(parts[0]) || !IsIPv4(parts[1]) || cap <= 0 {
		return out
	}
	start, ok1 := ipv4ToUint32(parts[0])
	end, ok2 := ipv4ToUint32(parts[1])
	if !ok1 || !ok2 || end < start {
		return out
	}
	for v := start; v <= end && len(out) < cap; v++ {
		out = append(out, uint32ToIPv4(v))
	}
	return out
}

// expandCIDR enumerates all host IPs in a CIDR block up to cap.
// For IPv6 it delegates to expandIPv6CIDR. For IPv4 it skips network+broadcast
// for prefixes > /30.
// Source: ScanTargetPlanner.java expandCidr()
func expandCIDR(cidr string, cap int) []string {
	var out []string
	parts := strings.SplitN(cidr, "/", 2)
	if len(parts) != 2 || !IsIPAddress(parts[0]) {
		return out
	}
	if strings.Contains(parts[0], ":") {
		prefix, err := strconv.Atoi(parts[1])
		if err != nil {
			return out
		}
		return expandIPv6CIDR(parts[0], prefix, cap)
	}
	// IPv4
	base, ok := ipv4ToUint32(parts[0])
	if !ok {
		return out
	}
	prefix, err := strconv.Atoi(parts[1])
	if err != nil || prefix < 0 || prefix > 32 {
		return out
	}
	var mask uint32
	if prefix == 0 {
		mask = 0
	} else {
		mask = ^uint32((1 << uint(32-prefix)) - 1)
	}
	network := base & mask
	broadcast := network | ^mask
	size := broadcast - network + 1
	var first, last uint32
	if size <= 2 {
		first = network
		last = broadcast
	} else {
		first = network + 1
		last = broadcast - 1
	}
	for v := first; v <= last && len(out) < cap; v++ {
		out = append(out, uint32ToIPv4(v))
	}
	return out
}

// expandIPv6CIDR enumerates the first cap host addresses in an IPv6 CIDR.
// Source: ScanTargetPlanner.java expandIpv6Cidr()
func expandIPv6CIDR(ipText string, prefix, cap int) []string {
	var out []string
	if prefix < 0 || prefix > 128 || cap <= 0 {
		return out
	}
	ip := net.ParseIP(ipText)
	if ip == nil {
		return out
	}
	ip = ip.To16()
	ipInt := new(big.Int).SetBytes(ip)

	// Build mask: 128-bit all-ones then left-shift host bits to zero
	all := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	var mask *big.Int
	if prefix == 0 {
		mask = big.NewInt(0)
	} else {
		mask = new(big.Int).Lsh(new(big.Int).Rsh(all, uint(128-prefix)), uint(128-prefix))
	}
	network := new(big.Int).And(ipInt, mask)
	size := new(big.Int).Lsh(big.NewInt(1), uint(128-prefix))

	current := new(big.Int).Set(network)
	if size.Cmp(big.NewInt(1)) > 0 {
		current.Add(current, big.NewInt(1)) // skip network address
	}
	for i := 0; i < cap; i++ {
		diff := new(big.Int).Sub(current, network)
		if diff.Cmp(size) >= 0 {
			break
		}
		raw := current.Bytes()
		b := make([]byte, 16)
		src := len(raw) - 16
		if src < 0 {
			src = 0
		}
		copy(b[16-len(raw[src:]):], raw[src:])
		addr := net.IP(b)
		out = append(out, addr.String())
		current.Add(current, big.NewInt(1))
	}
	return out
}

func uint32ToIPv4(v uint32) string {
	return strconv.Itoa(int(v>>24&0xff)) + "." +
		strconv.Itoa(int(v>>16&0xff)) + "." +
		strconv.Itoa(int(v>>8&0xff)) + "." +
		strconv.Itoa(int(v&0xff))
}

// ---------------------------------------------------------------------------
// Token counting helpers
// Source: ScanTargetPlanner.java estimateExpandedTargetCount()
// ---------------------------------------------------------------------------

// EstimateExpandedTargetCount estimates total IPs for a collection of tokens.
// CIDR and range tokens are estimated; plain IPs/hostnames count as 1 each.
// perEntryCap limits individual CIDR/range expansion to avoid int overflow.
// Source: ScanTargetPlanner.java estimateExpandedTargetCount()
func EstimateExpandedTargetCount(raw []string, perEntryCap int) int {
	var total int64
	for _, value := range raw {
		clean := CleanTargetToken(value)
		if clean == "" {
			continue
		}
		var n int
		if LooksLikeCIDR(clean) {
			n = EstimateCIDRCount(clean, perEntryCap)
		} else if LooksLikeIPv4Range(clean) {
			n = EstimateRangeCount(clean, perEntryCap)
		} else {
			n = 1
		}
		total += int64(n)
		if total > int64(^uint(0)>>1) {
			return int(^uint(0) >> 1)
		}
	}
	return int(total)
}

// EffectiveScanCap returns the actual cap after applying the user-chosen target cap.
// targetCap <= 0 means unlimited.
// Source: ScanTargetPlanner.java effectiveScanCap()
func EffectiveScanCap(targetCap, estimatedTargets int) int {
	if estimatedTargets < 0 {
		estimatedTargets = 0
	}
	if targetCap <= 0 {
		return estimatedTargets
	}
	if estimatedTargets < targetCap {
		return estimatedTargets
	}
	return targetCap
}

// ScanLimitLabel returns a human-readable label for a target cap.
// Source: ScanTargetPlanner.java scanLimitLabel()
func ScanLimitLabel(targetCap int) string {
	if targetCap <= 0 {
		return "unlimited"
	}
	// Format with commas (simplified)
	s := strconv.Itoa(targetCap)
	if len(s) <= 3 {
		return s
	}
	// Insert thousands separator
	var b strings.Builder
	mod := len(s) % 3
	if mod > 0 {
		b.WriteString(s[:mod])
	}
	for i := mod; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// DNS resolve (hostname → IPs, IPv6 first then IPv4)
// Source: ScanTargetPlanner.java resolve()
// ---------------------------------------------------------------------------

// ResolveScanTarget resolves a hostname to IP addresses.
// If the token is already an IP, returns it directly.
// Orders: IPv6 first, then IPv4 (deduplicated).
// Source: ScanTargetPlanner.java resolve()
func ResolveScanTarget(target string) []string {
	target = strings.TrimSpace(target)
	if IsIPAddress(target) {
		return []string{target}
	}
	addrs, err := net.LookupHost(target)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var ipv6, ipv4 []string
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || seen[a] {
			continue
		}
		seen[a] = true
		if ip.To4() == nil {
			ipv6 = append(ipv6, a)
		} else {
			ipv4 = append(ipv4, a)
		}
	}
	return append(ipv6, ipv4...)
}

// ---------------------------------------------------------------------------
// Diagnostic DNS test hosts (canonical list)
// Source: MaybeScanner/NetworkDiagnosticsRunner.java
// ---------------------------------------------------------------------------

// DiagnosticDNSHosts are the hostnames used in the network diagnostic DNS test.
// "aparat.com" is an Iranian CDN — it tests whether Iranian DNS is accessible.
// Source: NetworkDiagnosticsRunner.java dnsHosts array
var DiagnosticDNSTestHosts = []string{
	"one.one.one.one",
	"dns.google",
	"aparat.com",
}

// DiagnosticTCPProbes are the well-known IPs probed over port 443 to measure TCP latency.
// Source: NetworkDiagnosticsRunner.java tcpHosts array
type DiagnosticTCPProbe struct {
	Name string
	IP   string
	Port int
}

var DiagnosticTCPProbeTargets = []DiagnosticTCPProbe{
	{"Cloudflare", "1.1.1.1", 443},
	{"Google DNS", "8.8.8.8", 443},
	{"Akamai DNS", "184.26.160.25", 443},
}

// DiagnosticHTTPSTargets are the URLs probed by the HTTPS handshake test.
// Source: NetworkDiagnosticsRunner.java httpsTargets array
var DiagnosticHTTPSTargets = []string{
	"https://1.1.1.1",
	"https://8.8.8.8",
	"https://www.google.com",
}

// DiagnosticPublicIPEndpoint is the URL used to look up the device's public IP.
// Source: NetworkDiagnosticsRunner.java publicIpURL
const DiagnosticPublicIPEndpoint = "https://api.ipify.org?format=json"

// DiagnosticHTTPSConnectTimeoutMs is the connect+read timeout for diagnostic HTTPS probes.
// Source: NetworkDiagnosticsRunner.java connectTimeout/readTimeout
const DiagnosticHTTPSConnectTimeoutMs = 2500

// DiagnosticTCPConnectTimeoutMs is the connect timeout for diagnostic TCP probes.
// Source: NetworkDiagnosticsRunner.java Socket.connect(..., 2000)
const DiagnosticTCPConnectTimeoutMs = 2000

// ---------------------------------------------------------------------------
// Workflow engine orchestration constants
// Source: MaybeScanner/ScanWorkflowEngine.java
// ---------------------------------------------------------------------------

// WorkflowProfile indices.
const (
	WorkflowProfileTCP    = 0 // TCP connect only
	WorkflowProfileTLS    = 1 // TCP + TLS handshake
	WorkflowProfileHTTP   = 2 // TCP + TLS + HTTP probe
	WorkflowProfileVerify = 3 // full verification (HTTP, break on first HTTP pass)
)

// SNI selection strategy within a workflow step.
// Source: ScanWorkflowEngine.java scanTarget() candidates logic
//
//   profile >= 2 → allSni = true (probe all SNIs)
//   profile < 2  → first SNI only (or hostname if target is a hostname)
//
// tcpConnectedOnce guards: if TCP fails for the first SNI, skip remaining SNIs.
// break-on-first-http-pass applies for profile == 3 (Verify).
const (
	WorkflowSNIBreakThresholdProfile = 2   // profiles >= this use allSNI
	WorkflowHTTPBreakProfile         = 3   // break on first HTTP pass
	WorkflowBasebandPauseMs          = 200 // poll interval while baseband settling
	WorkflowBasebandMaxWaitMs        = 5000 // max wait per-target for settling
)

// DNS ndjson result field names from sidecar DNS query.
// Source: ScanWorkflowEngine.java inline DNS parsing
const (
	SidecarDNSResultType        = "dns"
	SidecarDNSResultFieldType   = "type"
	SidecarDNSResultFieldResult = "result"
	SidecarDNSAttemptTransport  = "transport"
	SidecarDNSAttemptOutcome    = "outcome"
	SidecarDNSAttemptLatencyMs  = "latency_ms"
	SidecarDNSAttemptErrorCode  = "error_code"
	SidecarDNSFieldCacheStatus  = "cache_status"
	SidecarDNSFieldAnswers      = "answers"
	SidecarDNSFieldAttempts     = "attempts"
)

// ---------------------------------------------------------------------------
// ScanCommandKind — scan lifecycle commands
// Source: MaybeScanner/ScanCommand.java Kind enum
// ---------------------------------------------------------------------------

type ScanCommandKind string

const (
	ScanCommandStartScan              ScanCommandKind = "START_SCAN"
	ScanCommandCancelScan             ScanCommandKind = "CANCEL_SCAN"
	ScanCommandClearSession           ScanCommandKind = "CLEAR_SESSION"
	ScanCommandStopSidecar            ScanCommandKind = "STOP_SIDECAR"
	ScanCommandExportResults          ScanCommandKind = "EXPORT_RESULTS"
	ScanCommandRefreshProviderReadiness ScanCommandKind = "REFRESH_PROVIDER_READINESS"
)

// ScanCommand is an immutable lifecycle instruction routed to the scan service.
// Source: MaybeScanner/ScanCommand.java
type ScanCommand struct {
	Kind          ScanCommandKind
	Generation    int64
	Source        string
	IssuedAtMs    int64
}

// ---------------------------------------------------------------------------
// ScanExportSpec — export format + redaction
// Source: MaybeScanner/ScanExportSpec.java
// ---------------------------------------------------------------------------

// SessionExportFormat is the in-service export format (different from ResultExportFormatter UI formats).
const (
	SessionExportJSONL    = 0
	SessionExportCSV      = 1
	SessionExportMarkdown = 2
	SessionExportNmapXML  = 3
)

// SessionExportSpec describes how to serialise a completed scan session to disk.
// Source: MaybeScanner/ScanExportSpec.java
type SessionExportSpec struct {
	Format       int    // SessionExport* constants
	RedactionMode string // "none" | redaction strategy
	ProductMode  string // "ip_first" | "route_pairing"
	FilePrefix   string // e.g. "maybescanner_export"
}

// DefaultSessionExportSpec returns the default export specification.
func DefaultSessionExportSpec() SessionExportSpec {
	return SessionExportSpec{
		Format:       SessionExportJSONL,
		RedactionMode: "none",
		ProductMode:  "ip_first",
		FilePrefix:   "maybescanner_export",
	}
}
