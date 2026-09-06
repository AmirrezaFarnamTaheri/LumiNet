package scanner

// scanner_target_plan.go — TargetPlan v1, TargetExpansionMeta, ScanLaunchSpec,
// LocalObservationHistoryStore, ScanProcessContinuity, ScanTerminalReason.
// Source: MaybeScanner Java source (exhaustive audit, all files read)

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// ScanTerminalReason — canonical lifecycle terminal states
// Source: MaybeScanner/ScanTerminalReason.java
// ---------------------------------------------------------------------------

// ScanTerminalReason identifies why a scan session ended.
type ScanTerminalReason string

const (
	ScanTerminalCompleted          ScanTerminalReason = "completed"
	ScanTerminalStoppedUI          ScanTerminalReason = "stopped"
	ScanTerminalStoppedNotification ScanTerminalReason = "stopped"
	ScanTerminalCleared            ScanTerminalReason = "idle"
	ScanTerminalFailedExport       ScanTerminalReason = "failed"
	ScanTerminalFailedStart        ScanTerminalReason = "failed"
	ScanTerminalFailedSidecar      ScanTerminalReason = "failed"
	ScanTerminalFailedProvider     ScanTerminalReason = "failed"
	ScanTerminalFailedStorage      ScanTerminalReason = "failed"
	ScanTerminalFailedNoChecks     ScanTerminalReason = "failed"
	ScanTerminalProcessLost        ScanTerminalReason = "process_lost"
)

// TerminalReasonLifecycleState returns the abstract lifecycle state for a terminal reason.
// Source: MaybeScanner/ScanTerminalReason.java lifecycleState field
func TerminalReasonLifecycleState(reason ScanTerminalReason) string {
	return string(reason)
}

// TerminalReasonFromStopSource determines the terminal reason based on stop source.
// Source: MaybeScanner/ScanTerminalReason.java fromStopRequested()
func TerminalReasonFromStopSource(stopRequested bool, source string) ScanTerminalReason {
	if !stopRequested {
		return ScanTerminalCompleted
	}
	if source == "notification" || source == "notification_legacy" {
		return ScanTerminalStoppedNotification
	}
	return ScanTerminalStoppedUI
}

// ---------------------------------------------------------------------------
// SidecarHeartbeatPolicy — state machine for mid-scan heartbeat loss
// Source: MaybeScanner/SidecarHeartbeatPolicy.java
// ---------------------------------------------------------------------------

// HeartbeatAction is the action the guard takes on each heartbeat probe.
type HeartbeatAction int

const (
	HeartbeatNoop               HeartbeatAction = 0 // guard not active, do nothing
	HeartbeatStopOnly           HeartbeatAction = 1 // session stopped externally, stop guard
	HeartbeatReschedule         HeartbeatAction = 2 // sidecar alive, probe again later
	HeartbeatFailSidecarAndStop HeartbeatAction = 3 // sidecar was alive but lost, abort scan
)

// HeartbeatGuardIntervalMs is the interval between sidecar heartbeat probes during a scan.
// Source: MaybeScanner/SidecarHeartbeatGuard.java INTERVAL_MS
const HeartbeatGuardIntervalMs = 5000

// DecideHeartbeatAction returns what the heartbeat guard should do given current state.
// Source: MaybeScanner/SidecarHeartbeatPolicy.java decide()
func DecideHeartbeatAction(active, sessionRunning, snapshotReachable, sidecarWasReachable bool) HeartbeatAction {
	if !active {
		return HeartbeatNoop
	}
	if !sessionRunning {
		return HeartbeatStopOnly
	}
	if snapshotReachable {
		return HeartbeatReschedule
	}
	if sidecarWasReachable {
		return HeartbeatFailSidecarAndStop
	}
	return HeartbeatStopOnly
}

// ---------------------------------------------------------------------------
// SidecarLauncher constants
// Source: MaybeScanner/SidecarLauncher.java
// ---------------------------------------------------------------------------

const (
	// SidecarBinaryName is the filename of the compiled sidecar binary.
	SidecarBinaryName = "maybescanner-sidecar"

	// SidecarEdgeBinaryName is the variant for MaybeEdgeScanner.
	SidecarEdgeBinaryName = "maybeedgescanner-sidecar"

	// SidecarHeartbeatWaitMs is the delay between each heartbeat probe during startup.
	// Source: MaybeScanner/SidecarLauncher.java HEARTBEAT_WAIT_MS
	SidecarHeartbeatWaitMs = 250

	// SidecarHeartbeatAttempts is the maximum number of heartbeat probes after launch.
	// Total startup wait = 250ms * 12 = 3s.
	// Source: MaybeScanner/SidecarLauncher.java HEARTBEAT_ATTEMPTS
	SidecarHeartbeatAttempts = 12

	// SidecarTokenEnvVar is the environment variable name used to pass the auth token to the sidecar.
	// Source: MaybeScanner/SidecarTokenStore.java ENV_NAME
	SidecarTokenEnvVar = "MAYBESCANNER_SIDECAR_TOKEN"

	// SidecarEdgeTokenEnvVar is the edge scanner variant.
	SidecarEdgeTokenEnvVar = "MAYBEEDGESCANNER_SIDECAR_TOKEN"

	// SidecarDisableCapsGuardsEnvVar disables capability guards in the sidecar.
	// Source: MaybeScanner/SidecarLauncher.java "DISABLE_CAPS_GUARDS"
	SidecarDisableCapsGuardsEnvVar = "DISABLE_CAPS_GUARDS"

	// SidecarTokenBytes is the number of random bytes for the sidecar auth token.
	// Source: MaybeScanner/SidecarTokenStore.java generateTokenHex(32)
	SidecarTokenBytes = 32

	// SidecarAssetPathTemplate is the template for the ABI-specific sidecar asset.
	// Format: "sidecar/<abi>/maybescanner-sidecar"
	// Source: MaybeScanner/SidecarLauncher.java assetPathForAbi()
	SidecarAssetPathTemplate = "sidecar/%s/maybescanner-sidecar"

	// SidecarInstallRelPath is the relative install path for the sidecar binary.
	// Source: MaybeScanner/SidecarLauncher.java resolveBinary()
	SidecarInstallRelPath = "sidecar/maybescanner-sidecar"
)

// SidecarLaunchErrors are the canonical error detail strings from the launcher.
// Source: MaybeScanner/SidecarLauncher.java
const (
	SidecarErrMissingBinary    = "sidecar_binary_missing"
	SidecarErrLaunchTimeout    = "sidecar_launch_timeout"
	SidecarErrLaunchFailed     = "sidecar_launch_failed"
	SidecarStatusAlreadyRunning = "already_running"
)

// ---------------------------------------------------------------------------
// TargetExpansionMeta — CIDR/range expansion context
// Source: MaybeScanner/TargetExpansionMeta.java
// ---------------------------------------------------------------------------

// TargetExpansionMeta carries expansion context when a CIDR or range token is
// expanded into individual IP addresses. Attached to each expanded IP so results
// can be correlated back to the parent CIDR/range.
// Source: MaybeScanner/TargetExpansionMeta.java
type TargetExpansionMeta struct {
	ParentToken      string // the original CIDR/range token (e.g. "10.0.0.0/24")
	Index            int    // position of this IP within the expansion
	TotalTheoretical int    // full CIDR/range size (before capping)
	TotalCapped      int    // number actually expanded (after cap)
	SkippedCount     int    // TotalTheoretical - TotalCapped
	SamplingSeed     string // stable seed for sampling ("seed-<8hexchars>")
}

// HasExpansion returns true if this meta represents an expanded child (not a plain token).
func (m *TargetExpansionMeta) HasExpansion() bool {
	return m != nil && m.ParentToken != "" && m.Index >= 0
}

// NewExpansionMeta creates a TargetExpansionMeta for an IP expanded from a CIDR/range.
// Source: MaybeScanner/TargetExpansionMeta.java forExpandedMember()
func NewExpansionMeta(parentToken string, index, totalTheoretical, totalCapped int) TargetExpansionMeta {
	if totalTheoretical < 0 {
		totalTheoretical = 0
	}
	if totalCapped < 0 {
		totalCapped = 0
	}
	skipped := totalTheoretical - totalCapped
	if skipped < 0 {
		skipped = 0
	}
	return TargetExpansionMeta{
		ParentToken:      strings.TrimSpace(parentToken),
		Index:            index,
		TotalTheoretical: totalTheoretical,
		TotalCapped:      totalCapped,
		SkippedCount:     skipped,
		SamplingSeed:     stableExpansionSeed(parentToken, totalCapped),
	}
}

// stableExpansionSeed computes the "seed-<8hex>" string for an expansion group.
// Source: MaybeScanner/TargetExpansionMeta.java stableSeed()
func stableExpansionSeed(parentToken string, capped int) string {
	seed := fmt.Sprintf("%s|cap=%d", parentToken, capped)
	h := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("seed-%02x%02x%02x%02x", h[0], h[1], h[2], h[3])
}

// ---------------------------------------------------------------------------
// TargetPlan v1 — probe job descriptor attached to each scan result
// Source: MaybeScanner/TargetPlanRecord.java
// ---------------------------------------------------------------------------

// TargetKind identifies the type of a scan target token.
type TargetKind string

const (
	TargetKindIP       TargetKind = "ip"
	TargetKindCIDR     TargetKind = "cidr"
	TargetKindRange    TargetKind = "range"
	TargetKindHostname TargetKind = "hostname"
)

// TargetPlanProductMode identifies which probe pipeline product produced this plan.
type TargetPlanProductMode string

const (
	TargetPlanIpFirst     TargetPlanProductMode = "ip_first"
	TargetPlanRoutePairing TargetPlanProductMode = "route_pairing"
)

// SNIMode describes how the SNI hostname was chosen.
type SNIMode string

const (
	SNIModeNone         SNIMode = "none"
	SNIModeFromHostname SNIMode = "from_hostname"
	SNIModeExplicit     SNIMode = "explicit"
)

// TargetPlan is a v1 schema-versioned probe job descriptor.
// Encodes the exact probe inputs, dedupe key, plan_id (stable SHA-256 prefix),
// and result correlation ID. Attached to every scan result.
// Source: MaybeScanner/TargetPlanRecord.java
type TargetPlan struct {
	SchemaVersion   int                   // always 1
	PlanID          string                // "plan-<8hex>" SHA-256 prefix of dedupe key
	CorrelationID   string                // "corr-<8hex>" SHA-256 prefix of dedupe key
	ProductMode     TargetPlanProductMode
	RawToken        string // original user input (or IP if no token)
	SourceType      string // "manual"
	SourceProvider  string // "manual"
	CorpusRevision  string // empty = null
	NormalizedKind  TargetKind
	OriginalHostname string // set only for hostname kind
	ResolvedIP      string // pre-resolved IP (or empty)
	IPFamily        string // "ipv4" | "ipv6" | "unknown"
	Port            int
	SNIHost         string
	SNIMode         SNIMode
	HTTPHost        string // same as SNIHost when SNI pairing enabled
	VerificationHost string // same as HTTPHost
	DNSMode         string // "pre_resolved" | "system"
	ResolverID      string // empty = null
	ALPNPolicy      string // "http1_http2"
	RouteID         string
	RouteType       string
	NetworkPath     string
	SafetyStatus    string // "allowed"
	DedupeKey       string
	ResultCorrelationID string

	// Expansion fields (null when not from CIDR/range)
	ExpansionParent       string
	ExpansionIndex        int
	ExpansionTheoretical  int
	ExpansionCapped       int
	ExpansionSkipped      int
	SamplingSeed          string
}

// BuildTargetPlan builds a TargetPlan v1 for a direct IP probe.
// Source: MaybeScanner/TargetPlanRecord.java forIpFirstProbe() → build()
func BuildTargetPlan(rawToken, resolvedIP string, port int, sniHost string, sniPairingEnabled bool, expansion *TargetExpansionMeta) TargetPlan {
	return buildTargetPlan(TargetPlanIpFirst, rawToken, resolvedIP, port, sniHost,
		sniPairingEnabled, "direct-default", "direct", "direct", expansion)
}

// BuildRoutePairingTargetPlan builds a TargetPlan for a VPN-routed probe.
// Source: MaybeScanner/TargetPlanRecord.java forRoutePairingProbe()
func BuildRoutePairingTargetPlan(rawToken, resolvedIP string, port int, sniHost string,
	sniPairingEnabled bool, routeID, routeType, networkPath string) TargetPlan {
	return buildTargetPlan(TargetPlanRoutePairing, rawToken, resolvedIP, port, sniHost,
		sniPairingEnabled, routeID, routeType, networkPath, nil)
}

func buildTargetPlan(productMode TargetPlanProductMode, rawToken, resolvedIP string, port int, sniHost string,
	sniPairingEnabled bool, routeID, routeType, networkPath string, expansion *TargetExpansionMeta) TargetPlan {
	token := strings.TrimSpace(rawToken)
	ip := strings.TrimSpace(resolvedIP)
	sni := strings.TrimSpace(sniHost)

	// If this is an expanded member, use the parent token as the canonical token
	if expansion != nil && expansion.HasExpansion() {
		token = expansion.ParentToken
	}

	kind := classifyTargetKind(token, ip, expansion)
	sniMode := sniModeFor(kind, sni, sniPairingEnabled)
	hostname := hostnameFor(token, kind)
	httpHost := httpHostFor(kind, sni, sniPairingEnabled)
	ipFamily := ipFamilyFor(ip)
	dnsMode := "pre_resolved"
	if ip == "" {
		dnsMode = "system"
	}

	identity := identityForDedupe(token, ip)
	dedupeKey := buildDedupeKey(productMode, identity, port, sniMode, sni, httpHost, routeID, expansion)
	planID := stableID("plan", dedupeKey)
	correlationID := stableID("corr", dedupeKey)

	t := rawToken
	if t == "" {
		t = ip
	}

	plan := TargetPlan{
		SchemaVersion:       1,
		PlanID:              planID,
		CorrelationID:       correlationID,
		ProductMode:         productMode,
		RawToken:            t,
		SourceType:          "manual",
		SourceProvider:      "manual",
		NormalizedKind:      kind,
		OriginalHostname:    hostname,
		ResolvedIP:          ip,
		IPFamily:            ipFamily,
		Port:                port,
		SNIHost:             sni,
		SNIMode:             sniMode,
		HTTPHost:            httpHost,
		VerificationHost:    httpHost,
		DNSMode:             dnsMode,
		ALPNPolicy:          "http1_http2",
		RouteID:             strings.TrimSpace(routeID),
		RouteType:           strings.TrimSpace(routeType),
		NetworkPath:         strings.TrimSpace(networkPath),
		SafetyStatus:        "allowed",
		DedupeKey:           dedupeKey,
		ResultCorrelationID: correlationID,
	}
	if sniMode == SNIModeNone || sni == "" {
		plan.SNIHost = ""
	}
	if expansion != nil && expansion.HasExpansion() {
		plan.ExpansionParent = expansion.ParentToken
		plan.ExpansionIndex = expansion.Index
		plan.ExpansionTheoretical = expansion.TotalTheoretical
		plan.ExpansionCapped = expansion.TotalCapped
		plan.ExpansionSkipped = expansion.SkippedCount
		plan.SamplingSeed = expansion.SamplingSeed
	}
	return plan
}

func classifyTargetKind(token, ip string, expansion *TargetExpansionMeta) TargetKind {
	if expansion != nil && expansion.HasExpansion() {
		return TargetKindIP
	}
	if token == "" || isIPAddress(ip) {
		return TargetKindIP
	}
	if strings.Contains(token, "/") {
		return TargetKindCIDR
	}
	parts := strings.SplitN(token, "-", 2)
	if len(parts) == 2 {
		_, ok1 := ipv4ToUint32(parts[0])
		_, ok2 := ipv4ToUint32(parts[1])
		if ok1 && ok2 {
			return TargetKindRange
		}
	}
	return TargetKindHostname
}

func isIPAddress(s string) bool {
	if s == "" {
		return false
	}
	// Simple check: contains only digits, dots, colons, hex chars
	hasColon := strings.Contains(s, ":")
	if hasColon {
		return true // treat as IPv6
	}
	_, ok := ipv4ToUint32(s)
	return ok
}

func sniModeFor(kind TargetKind, sni string, sniPairingEnabled bool) SNIMode {
	if !sniPairingEnabled || sni == "" {
		return SNIModeNone
	}
	if kind == TargetKindHostname {
		return SNIModeFromHostname
	}
	return SNIModeExplicit
}

func hostnameFor(token string, kind TargetKind) string {
	if kind == TargetKindHostname {
		return token
	}
	return ""
}

func httpHostFor(kind TargetKind, sni string, sniPairingEnabled bool) string {
	if !sniPairingEnabled || sni == "" {
		return ""
	}
	return sni
}

func ipFamilyFor(ip string) string {
	if ip == "" {
		return "unknown"
	}
	if strings.Contains(ip, ":") {
		return "ipv6"
	}
	_, ok := ipv4ToUint32(ip)
	if ok {
		return "ipv4"
	}
	return "unknown"
}

func identityForDedupe(token, ip string) string {
	if ip != "" {
		return "ip=" + ip
	}
	if token != "" {
		return "raw=" + token
	}
	return "raw="
}

func buildDedupeKey(productMode TargetPlanProductMode, identity string, port int, sniMode SNIMode, sni, httpHost, routeID string, expansion *TargetExpansionMeta) string {
	var base string
	if productMode == TargetPlanRoutePairing {
		base = fmt.Sprintf("%s|%s|%d|sni=%s|host=%s|route=%s", productMode, identity, port, sni, httpHost, routeID)
	} else {
		sniPart := "no_sni"
		if sniMode != SNIModeNone {
			sniPart = sni
		}
		base = fmt.Sprintf("%s|%s|%d|%s|%s", productMode, identity, port, sniPart, routeID)
	}
	if expansion != nil && expansion.HasExpansion() {
		base = fmt.Sprintf("%s|parent=%s|idx=%d", base, expansion.ParentToken, expansion.Index)
	}
	return base
}

// stableID computes a "prefix-<8hex>" string from the first 4 bytes of SHA-256(seed).
// Source: MaybeScanner/TargetPlanRecord.java stableId()
func stableID(prefix, seed string) string {
	h := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("%s-%02x%02x%02x%02x", prefix, h[0], h[1], h[2], h[3])
}

// ---------------------------------------------------------------------------
// ScanLaunchSpec — immutable scan job parameters
// Source: MaybeScanner/ScanLaunchSpec.java
// ---------------------------------------------------------------------------

// TLSMode controls how TLS is verified during scanning.
type TLSMode int

const (
	TLSModeNone        TLSMode = 0 // no TLS probing
	TLSModeVerify      TLSMode = 1 // verify server cert
	TLSModeSkipVerify  TLSMode = 2 // accept any cert (for CDN IPs with SNI mismatch)
)

// ScanLaunchSpec is the immutable set of parameters staged before a scan starts.
// Serialised and sent to the background service worker.
// Source: MaybeScanner/ScanLaunchSpec.java
type ScanLaunchSpec struct {
	Generation        int64
	Targets           []string
	TargetExpansions  []*TargetExpansionMeta // parallel to Targets (nil for non-expanded)
	SNIs              []string
	Ports             []int
	WorkflowProfiles  []int    // ordered list of probe profiles to run (0=TCP,1=TLS,2=HTTP,3=Verify)
	Batch             int      // number of targets per batch (for progress tracking)
	Threads           int      // worker thread count
	TimeoutMs         int      // per-probe timeout in milliseconds
	TLSMode           TLSMode
	AllSNIPreference  bool     // probe all SNIs for each IP (not just the first match)
	SuppressNoisyLogs bool
	SNIPairingEnabled bool     // pair each IP with an SNI hostname for TLS/HTTP probing
	HTTPPath          string   // path for HTTP probing (e.g. "/")
}

// DefaultScanLaunchSpec returns a baseline launch spec for a standard scan.
func DefaultScanLaunchSpec(generation int64, targets, snis []string, ports []int) ScanLaunchSpec {
	if len(ports) == 0 {
		ports = []int{443}
	}
	return ScanLaunchSpec{
		Generation:       generation,
		Targets:          targets,
		SNIs:             snis,
		Ports:            ports,
		WorkflowProfiles: []int{0, 1}, // TCP then TLS
		Batch:            100,
		Threads:          64,
		TimeoutMs:        DefaultTCPTimeoutMs,
		TLSMode:          TLSModeSkipVerify,
		SNIPairingEnabled: len(snis) > 0,
	}
}

// ---------------------------------------------------------------------------
// LocalObservationHistoryStore — persistent IP:port success counter
// Source: MaybeScanner/LocalObservationHistoryStore.java
// ---------------------------------------------------------------------------

// ObservationEntry is a previously successful IP:port pair with its success count.
// Key format: "ip:port" (e.g. "1.1.1.1:443").
// Source: MaybeScanner/LocalObservationHistoryStore.java Entry
type ObservationEntry struct {
	Key   string // "ip:port"
	Count int    // number of times this IP:port passed TCP/TLS in past scans
}

// MergeObservationHistory merges newly successful IP:port keys into the history counter map.
// The map is "ip:port" → successCount. Deduplicates within a single run before incrementing.
// Source: MaybeScanner/LocalObservationHistoryStore.java mergeSuccessfulKeysJson()
func MergeObservationHistory(existing map[string]int, successfulKeys []string) map[string]int {
	if existing == nil {
		existing = make(map[string]int)
	}
	// Deduplicate within this run
	seenThisRun := make(map[string]bool)
	for _, key := range successfulKeys {
		key = strings.TrimSpace(key)
		if key != "" {
			seenThisRun[key] = true
		}
	}
	// Increment
	for key := range seenThisRun {
		existing[key] = existing[key] + 1
	}
	return existing
}

// TopStableObservations returns the top N entries from the history with count >= minCount,
// sorted descending by count (most reliable IPs first).
// Source: MaybeScanner/LocalObservationHistoryStore.java loadTopStableFromJson()
func TopStableObservations(history map[string]int, minCount, limit int) []ObservationEntry {
	var entries []ObservationEntry
	for key, count := range history {
		if count >= minCount {
			entries = append(entries, ObservationEntry{Key: key, Count: count})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})
	if limit > 0 && len(entries) > limit {
		return entries[:limit]
	}
	return entries
}

// ---------------------------------------------------------------------------
// ScanProcessContinuity — crash/process-restart detection
// Source: MaybeScanner/ScanProcessContinuityStore.java
// ---------------------------------------------------------------------------

// ScanProcessContinuityKeys are the persistence keys for continuity detection.
// Source: MaybeScanner/ScanProcessContinuityStore.java KEY_* constants
const (
	ContinuityKeyActive       = "active"
	ContinuityKeyGeneration   = "generation"
	ContinuityKeyPlannedChecks = "planned_checks"
	ContinuityKeyStartedAt    = "started_at"
	ContinuityKeyWorkflow     = "workflow"
	ContinuityPrefsName       = "scan_process_continuity"
)

// AbandonedSession is recovered after a crash/process-restart.
// The previous scan cannot be resumed — it is reported to the user.
// Source: MaybeScanner/ScanProcessContinuityStore.java AbandonedSession
type AbandonedSession struct {
	Generation       int64
	PlannedChecks    int
	StartedAtEpochMs int64
	Workflow         string
}

// AbandonedSessionDetail returns a user-facing message describing the abandoned session.
// Source: MaybeScanner/ScanProcessContinuityStore.java detail()
func (a *AbandonedSession) Detail() string {
	msg := "Previous scan could not be resumed after app process restart"
	if a.PlannedChecks > 0 {
		msg += fmt.Sprintf(" (%d planned checks)", a.PlannedChecks)
	}
	return msg
}

// ---------------------------------------------------------------------------
// ResultAnalyticsStats — latency bucket and protocol breakdown
// Source: MaybeScanner/ResultAnalyticsStats.java
// ---------------------------------------------------------------------------

// LatencyBucket classifies a result by total latency.
// Source: MaybeScanner/ResultAnalyticsStats.java from()
const (
	LatencyFastMaxMs     = 120  // < 120ms = fast
	LatencyMediumMaxMs   = 300  // 120–299ms = medium
	LatencySlowMaxMs     = 700  // 300–699ms = slow
	// >= 700ms = very slow
)

// NetworkKey normalises a network classification string to uppercase.
// Empty or nil → "UNKNOWN".
// Source: MaybeScanner/ResultAnalyticsStats.java networkKey()
func NetworkKey(classification string) string {
	classification = strings.TrimSpace(classification)
	if classification == "" {
		return "UNKNOWN"
	}
	return strings.ToUpper(classification)
}

// ResultAnalytics aggregates scan result statistics for a set of probe results.
// Source: MaybeScanner/ResultAnalyticsStats.java
type ResultAnalytics struct {
	Total         int
	HTTP          int // passed HTTP
	TLS           int // passed TLS only
	TCP           int // passed TCP only
	Down          int // failed all
	Fast          int // latency < 120ms
	Medium        int // 120–299ms
	Slow          int // 300–699ms
	VerySlow      int // >= 700ms
	NetworkGroups map[string]int // provider → count
}

// ---------------------------------------------------------------------------
// ResultSummaryStats — quality scoring and best-host ranking
// Source: MaybeScanner/ResultSummaryStats.java
// ---------------------------------------------------------------------------

// QualityScore computes the quality score for host ranking.
// Formula: quality + (httpPass?10:0) + (tlsPass?6:0) - max(0,latency)/1200.0
// Source: MaybeScanner/ResultSummaryStats.java bestHostLine()
func QualityScore(baseQuality float64, httpPass, tlsPass bool, totalLatencyMs int64) float64 {
	score := baseQuality
	if httpPass {
		score += 10
	}
	if tlsPass {
		score += 6
	}
	if totalLatencyMs > 0 {
		score -= float64(totalLatencyMs) / 1200.0
	}
	return score
}

// ---------------------------------------------------------------------------
// ScanInputAnalyzer — input token validation
// Source: MaybeScanner/ScanInputAnalyzer.java
// ---------------------------------------------------------------------------

// DomainRegex is the regex pattern for valid domain tokens.
// Source: MaybeScanner/ScanInputAnalyzer.java validDomainToken()
const DomainRegex = `(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`

// InputStats summarises an analysis of raw scan target input.
// Source: MaybeScanner/ScanInputAnalyzer.java InputStats
type InputStats struct {
	Lines       int
	Items       int
	Valid        int
	Invalid      int
	Duplicates   int
	IPs          int
	CIDRs        int
	Ranges       int
	Hostnames    int
	EstimatedIPs int64
	Preview      []string // up to 12 unique valid tokens
}

// ---------------------------------------------------------------------------
// Result export formats
// Source: MaybeScanner/ResultExportFormatter.java
// ---------------------------------------------------------------------------

// ExportFormat defines the output format for scan result export.
// Source: MaybeScanner/ResultExportFormatter.java buildSelectedFormat()
type ExportFormat int

const (
	ExportFormatIPNewline     ExportFormat = 0 // IP addresses one per line
	ExportFormatIPComma       ExportFormat = 1 // IP addresses comma-separated
	ExportFormatIPWithSNI     ExportFormat = 2 // "ip:port hostname" or "ip:port sni" per line
	ExportFormatCSV           ExportFormat = 3 // CSV with header
	ExportFormatJSON          ExportFormat = 4 // JSON array of full result objects
)

// CSVExportHeader is the standard CSV header for scan result exports.
// Source: MaybeScanner/ResultExportFormatter.java CSV_HEADER
const CSVExportHeader = "target,ip,port,sni,tcp,tls,http,http_status,latency_ms,alpn,tls_profile,http3_hint,network_classification,quality,reason\n"

// ---------------------------------------------------------------------------
// ProviderHealthStats — per-CDN provider probe success stats
// Source: MaybeScanner/ProviderHealthStats.java
// ---------------------------------------------------------------------------

// ProviderHealthItem tracks probe outcomes per CDN provider classification.
// Source: MaybeScanner/ProviderHealthStats.java Item
type ProviderHealthItem struct {
	Name         string
	Total        int
	Working      int
	Timeout      int
	Reset        int
	LatencyCount int
	LatencySum   int64
}

// SuccessPercent returns the probe success rate as 0–100.
func (p *ProviderHealthItem) SuccessPercent() int {
	if p.Total == 0 {
		return 0
	}
	return int(float32(p.Working*100) / float32(p.Total) + 0.5)
}

// AvgLatencyMs returns the average latency, or -1 if no latency data.
func (p *ProviderHealthItem) AvgLatencyMs() int64 {
	if p.LatencyCount == 0 {
		return -1
	}
	return p.LatencySum / int64(p.LatencyCount)
}

// Label returns a human-readable summary line.
// Source: MaybeScanner/ProviderHealthStats.java Item.label()
func (p *ProviderHealthItem) Label() string {
	avg := "--"
	if p.LatencyCount > 0 {
		avg = fmt.Sprintf("%dms", p.AvgLatencyMs())
	}
	return fmt.Sprintf("%s: %d/%d pass, %d%%, avg %s, timeout %d, reset %d",
		p.Name, p.Working, p.Total, p.SuccessPercent(), avg, p.Timeout, p.Reset)
}

// ---------------------------------------------------------------------------
// Baseband settling constants
// Source: MaybeScanner/diagnostics/PrivilegedTelephonyBasebandManager.java
// ---------------------------------------------------------------------------

const (
	// BasebandSettlingWindowMs is the max time after a radio mutation to consider the
	// baseband as "settling". During settling, scan probes are paused up to 5s.
	// Source: PrivilegedTelephonyBasebandManager.java isBasebandSettling() 5000L
	BasebandSettlingWindowMs = 5000

	// BasebandRadioSettleMs is the delay between setPreferredNetworkType and readback.
	// Source: PrivilegedTelephonyBasebandManager.java RADIO_SETTLE_MS
	BasebandRadioSettleMs = 1500

	// BasebandBinderServiceKey is the Android system service name for the telephony binder.
	// Source: PrivilegedTelephonyBasebandManager.java BINDER_SERVICE_KEY
	BasebandBinderServiceKey = "phone"

	// BasebandScanPauseOnSettlingMs is the per-target wait when baseband is settling.
	// Source: ScanWorkflowEngine.java Thread.sleep(200L) poll loop
	BasebandScanPauseIntervalMs = 200

	// BasebandScanMaxWaitMs is the max time a single target probe waits for baseband to settle.
	// Source: ScanWorkflowEngine.java 5000L timeout
	BasebandScanMaxWaitMs = 5000
)

// ShizukuMode indicates whether Shizuku is running as root or ADB.
const (
	ShizukuModeRoot    = "root"    // shellUid == 0
	ShizukuModeADB     = "adb"     // shellUid == 2000
	ShizukuModeUnknown = "unknown"
)
