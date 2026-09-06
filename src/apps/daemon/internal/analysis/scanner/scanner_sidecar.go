package scanner

// scanner_sidecar.go — Sidecar API, PhaseResult, SourceCatalog, ResultFilter,
// EdgeRouteProfile, PsiphonReadiness, RouteOptions constants.
// Source: MaybeScanner + MaybeEdgeScanner (Android Java source, exhaustive audit)

import (
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Sidecar API Constants
// Source: MaybeScanner/SidecarController.java
// ---------------------------------------------------------------------------

const (
	// SidecarBaseURL is the loopback address where the scanner sidecar binary listens.
	SidecarBaseURL = "http://127.0.0.1:10808"

	// SidecarEndpointHeartbeat is the health/heartbeat endpoint (GET).
	// Response: {state, version, uptime_ms}
	SidecarEndpointHeartbeat = SidecarBaseURL + "/api/heartbeat"

	// SidecarEndpointShutdown is the graceful shutdown endpoint (POST, empty body).
	SidecarEndpointShutdown = SidecarBaseURL + "/api/shutdown"

	// SidecarEndpointProviderCorpus is the CDN provider corpus metadata endpoint (GET).
	// Response: {corpus_id, stale (bool), stale_after (timestamp string)}
	SidecarEndpointProviderCorpus = SidecarBaseURL + "/api/provider-corpus"

	// SidecarEndpointDNS is the DNS query endpoint (POST, ndjson response stream).
	// Body: {"domains":["..."],"resolvers":["1.1.1.1"],"qtypes":["A"],"timeout_ms":1500}
	// Each ndjson line: {"type":"dns","result":{cache_status, answers, attempts}}
	// DNS attempt fields: transport, outcome, latency_ms, error_code
	SidecarEndpointDNS = SidecarBaseURL + "/api/dns"

	// SidecarDNSDefaultResolvers is the default DNS resolver sent to the sidecar.
	SidecarDNSDefaultResolver = "1.1.1.1"

	// SidecarDNSTimeoutMs is the default per-query timeout sent to the sidecar DNS API.
	SidecarDNSTimeoutMs = 1500

	// SidecarHeartbeatTimeoutMs is the HTTP timeout for heartbeat probes.
	SidecarHeartbeatTimeoutMs = 1200

	// SidecarShutdownTimeoutMs is the HTTP timeout for shutdown requests.
	SidecarShutdownTimeoutMs = 2500

	// SidecarAuthHeaderBearer is the Authorization header sent with all sidecar requests.
	SidecarAuthHeaderBearer = "Authorization"

	// SidecarAuthHeaderToken is the secondary token header for sidecar auth.
	SidecarAuthHeaderToken = "X-Sidecar-Token"
)

// SidecarSnapshot is the state of the scanner sidecar at a point in time.
// Source: MaybeScanner/SidecarController.java SidecarSnapshot
type SidecarSnapshot struct {
	Reachable bool
	State     string // e.g. "idle", "scanning", "starting"
	Version   int
	UptimeMs  int64
	Detail    string // error detail when Reachable=false
}

// ---------------------------------------------------------------------------
// PhaseResult — Per-probe layer outcome
// Source: MaybeScanner/PhaseResult.java
// ---------------------------------------------------------------------------

// ProbePhase identifies which connectivity layer was tested.
type ProbePhase string

const (
	ProbePhaseDNS   ProbePhase = "dns"
	ProbePhaseTCP   ProbePhase = "tcp"
	ProbePhaseTLS   ProbePhase = "tls"
	ProbePhaseHTTP1 ProbePhase = "http1"
	ProbePhaseHTTP2 ProbePhase = "http2"
	ProbePhaseHTTP  ProbePhase = "http"
	ProbePhaseRoute ProbePhase = "route"
)

// ProbeStatus is the outcome of a single probe phase.
type ProbeStatus string

const (
	ProbeStatusSuccess     ProbeStatus = "success"
	ProbeStatusTimeout     ProbeStatus = "timeout"
	ProbeStatusRefused     ProbeStatus = "refused"
	ProbeStatusReset       ProbeStatus = "reset"
	ProbeStatusSkipped     ProbeStatus = "skipped"
	ProbeStatusUnsupported ProbeStatus = "unsupported"
	ProbeStatusFailed      ProbeStatus = "failed"
)

// PhaseResult holds the outcome of one probe phase for one target IP.
// Aligns with sidecar PhaseResult v1 JSON: {phase, status, duration_ms, retryable, error_code, evidence}
// Source: MaybeScanner/PhaseResult.java
type PhaseResult struct {
	Phase      ProbePhase
	Status     ProbeStatus
	DurationMs int64
	ErrorCode  string
	Retryable  bool
}

// ClassifyErrorCode maps an error message to a stable error code for a given phase.
// Source: MaybeScanner/PhaseResult.java classifyCode()
func ClassifyErrorCode(phase ProbePhase, errMsg string) string {
	prefix := "SCAN"
	switch phase {
	case ProbePhaseDNS:
		prefix = "DNS"
	case ProbePhaseTCP:
		prefix = "TCP_CONNECT"
	case ProbePhaseTLS:
		prefix = "TLS_HANDSHAKE"
	case ProbePhaseHTTP, ProbePhaseHTTP1, ProbePhaseHTTP2:
		prefix = "HTTP"
	case ProbePhaseRoute:
		prefix = "ROUTE"
	}
	lower := strings.ToLower(errMsg)
	switch {
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out") || strings.Contains(lower, "deadline exceeded"):
		return prefix + "_TIMEOUT"
	case strings.Contains(lower, "reset"):
		return prefix + "_RESET"
	case strings.Contains(lower, "refused"):
		return prefix + "_REFUSED"
	}
	return prefix + "_FAILED"
}

// IsRetryableErrorCode returns true for transient errors that warrant a retry.
// Source: MaybeScanner/PhaseResult.java retryableFromCode()
func IsRetryableErrorCode(code string) bool {
	return strings.HasSuffix(code, "_TIMEOUT") || strings.HasSuffix(code, "_RESET")
}

// HTTPPhaseFromALPN returns http2 if the ALPN contains "h2", else http1.
// Source: MaybeScanner/PhaseResult.java httpPhaseFromAlpn()
func HTTPPhaseFromALPN(alpn string) ProbePhase {
	if strings.Contains(strings.ToLower(alpn), "h2") {
		return ProbePhaseHTTP2
	}
	return ProbePhaseHTTP1
}

// ---------------------------------------------------------------------------
// SourceCatalog — CDN IP corpus asset names
// Source: MaybeScanner/SourceCatalog.java
// ---------------------------------------------------------------------------

const (
	CorpusDefaultTargets      = "default_targets.txt"
	CorpusDefaultIPSrcExtra   = "default_ip_sources_extra.txt"
	CorpusCommunityIPSources  = "scan-corpora/community-ip-sources.txt"
	CorpusCommunityIPCIDRs24  = "scan-corpora/community-ip-cidrs-24.txt"
	CorpusAkamaiAS20940       = "scan-corpora/akamai-AS20940.json"
	CorpusAkamaiHosts184x     = "scan-corpora/akamai-hosts-184x.txt"
	CorpusAWSCloudfrontRanges = "scan-corpora/aws-cloudfront-ranges.txt"
	CorpusFastlyAS54113       = "scan-corpora/fastly-AS54113.json"
	CorpusCloudflareRanges    = "scan-corpora/cloudflare-ranges.txt"
	CorpusGitHubPagesRanges   = "scan-corpora/github-pages-ranges.txt"
	CorpusAzureFrontDoor      = "scan-corpora/azure-frontdoor-ranges.txt"
	CorpusGoogleEdgeRanges    = "scan-corpora/google-cdn-ranges.txt"
	CorpusBunnyRanges         = "scan-corpora/bunny-ranges.txt"
	CorpusStackpathEdgio      = "scan-corpora/stackpath-edgio-ranges.txt"
	CorpusOtherCloudRanges    = "scan-corpora/other-cloud-ranges.txt"
)

// OtherNetworkCorpora lists all CDN range assets that are not major providers.
var OtherNetworkCorpora = []string{
	CorpusGitHubPagesRanges,
	CorpusAzureFrontDoor,
	CorpusGoogleEdgeRanges,
	CorpusBunnyRanges,
	CorpusStackpathEdgio,
	CorpusOtherCloudRanges,
}

// ---------------------------------------------------------------------------
// CIDR / Range Target Estimation
// Source: MaybeScanner/ScanTargetPlanner.java
// ---------------------------------------------------------------------------

// EstimateCIDRCount estimates the usable host count in a CIDR. Capped at cap.
// Subtracts network+broadcast for IPv4 /2 through /30.
// Source: MaybeScanner/ScanTargetPlanner.java estimateCidrCount()
func EstimateCIDRCount(cidr string, cap int) int {
	if cap <= 0 {
		return 0
	}
	parts := strings.SplitN(cidr, "/", 2)
	if len(parts) != 2 {
		return 0
	}
	prefix, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0
	}
	if strings.Contains(parts[0], ":") {
		// IPv6 — always cap
		if prefix < 0 || prefix > 128 {
			return 0
		}
		return cap
	}
	if prefix < 0 || prefix > 32 {
		return 0
	}
	size := int64(1) << uint(32-prefix)
	usable := size
	if size > 2 {
		usable = size - 2
	}
	if usable > int64(cap) {
		return cap
	}
	if usable < 0 {
		return 0
	}
	return int(usable)
}

// EstimateRangeCount estimates the count of IPs in a "A.B.C.D-E.F.G.H" range.
// Source: MaybeScanner/ScanTargetPlanner.java estimateRangeCount()
func EstimateRangeCount(rangeStr string, cap int) int {
	if cap <= 0 {
		return 0
	}
	parts := strings.SplitN(rangeStr, "-", 2)
	if len(parts) != 2 {
		return 0
	}
	start, ok1 := ipv4ToUint32(parts[0])
	end, ok2 := ipv4ToUint32(parts[1])
	if !ok1 || !ok2 || end < start {
		return 0
	}
	count := int64(end-start) + 1
	if count > int64(cap) {
		return cap
	}
	return int(count)
}

func ipv4ToUint32(ip string) (uint32, bool) {
	parts := strings.Split(strings.TrimSpace(ip), ".")
	if len(parts) != 4 {
		return 0, false
	}
	var result uint32
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return 0, false
		}
		result = (result << 8) | uint32(v)
	}
	return result, true
}

// ---------------------------------------------------------------------------
// ResultFilterSpec — Scan result filtering and sorting
// Source: MaybeScanner/ResultFilterEngine.java
// ---------------------------------------------------------------------------

// ResultSortMode defines how scan results are ordered.
type ResultSortMode int

const (
	ResultSortDefault        ResultSortMode = 0 // reverse insertion order
	ResultSortByLatency      ResultSortMode = 1 // ascending latency (lowest first)
	ResultSortByQuality      ResultSortMode = 2 // descending quality score
	ResultSortByProvider     ResultSortMode = 3 // group by provider, then quality
	ResultSortByHost         ResultSortMode = 4 // alphabetical by host hint
	ResultSortByHTTPThenQual ResultSortMode = 5 // HTTP pass first, then quality
	ResultSortByTLSThenQual  ResultSortMode = 6 // TLS pass first, then quality
)

// ResultFilterSpec defines the filtering criteria for scan result display.
// Source: MaybeScanner/ResultFilterEngine.java Spec
type ResultFilterSpec struct {
	RequireWorking             bool
	RequireTLSOrHTTP           bool
	RequireHTTP                bool
	RequireKnownClassification bool
	RequireTLS13               bool
	BestPerEndpoint            bool   // keep only the best result per (ip,port,sni)
	MaxLatencyMs               int    // 0 = no limit
	MinQuality                 float64
	SortMode                   ResultSortMode
	NetworkPreset              string // provider filter preset (e.g. "cloudflare", "akamai")
	NetworkText                string // free-text filter on provider classification
	CertText                   string // free-text filter on certificate text
	HostText                   string // free-text filter on host hint
}

// ProviderMatchesPreset checks if a CDN classification matches the user's provider preset.
// Source: MaybeScanner/ResultFilterEngine.java providerMatches()
func ProviderMatchesPreset(preset, provider string) bool {
	choice := strings.ToLower(strings.TrimSpace(preset))
	classification := strings.ToLower(strings.TrimSpace(provider))
	switch {
	case choice == "" || strings.HasPrefix(choice, "any"):
		return true
	case strings.HasPrefix(choice, "known"):
		return classification != "" && classification != "unknown"
	case strings.HasPrefix(choice, "unknown"):
		return classification == "" || classification == "unknown"
	case strings.Contains(choice, "cloudfront") || strings.Contains(choice, "aws"):
		return strings.Contains(classification, "cloudfront") || strings.Contains(classification, "aws") || strings.Contains(classification, "amazon")
	case strings.Contains(choice, "cloudflare"):
		return strings.Contains(classification, "cloudflare")
	case strings.Contains(choice, "akamai"):
		return strings.Contains(classification, "akamai")
	case strings.Contains(choice, "fastly"):
		return strings.Contains(classification, "fastly")
	case strings.Contains(choice, "github"):
		return strings.Contains(classification, "github")
	case strings.Contains(choice, "google"):
		return strings.Contains(classification, "google") || strings.Contains(classification, "gcp")
	case strings.Contains(choice, "azure"):
		return strings.Contains(classification, "azure") || strings.Contains(classification, "microsoft")
	case strings.Contains(choice, "bunny"):
		return strings.Contains(classification, "bunny")
	}
	return strings.Contains(classification, choice)
}

// ---------------------------------------------------------------------------
// EdgeRouteProfile — MaybeEdgeScanner VPN/proxy routing configuration
// Source: MaybeEdgeScanner/EdgeRouteProfile.java
// ---------------------------------------------------------------------------

// EdgeRouteProfile describes how the scanner routes traffic through an external
// VPN or proxy provider during edge scanning. Serialised as schema_version=1 JSON
// to the sidecar /api/route endpoint.
type EdgeRouteProfile struct {
	Enabled       bool
	RouteID       string
	PluginID      string // "psiphon", "windscribe", ""
	ProviderID    string
	ProtocolMode  string // see RouteProtocol* constants
	AuthMode      string // see RouteAuth* constants
	DNSPolicy     string // see RouteDNS* constants
	SplitTunnel   string // see RouteSplit* constants
	UpstreamMode  string // see RouteUpstream* constants
	Downstream    string // see RouteDownstream* constants
	GatewayMode   string // "loopback_only" | "lan_shared"
	RouteBinding  string
	RouteStrategy string // see RouteStrategy* constants
	ConduitMode   string // "auto" | "shirokhorshid" | "public"
	ProviderChain string // see RouteChain* constants

	// CDN fronting (Psiphon-specific)
	FrontingIPRef string
	FrontingSNI   string
	BeastMode     bool // aggressive/beast mode

	ChainUpstreamRef string
	GatewayAuthRef   string
	LANSocksPort     string
	LANHTTPPort      string
	ProfileRef       string
	CredentialRef    string
	ConfigRef        string
	Endpoint         string // "socks5://127.0.0.1:1080" | "http://..."
	PackageName      string // for external_vpn_apk
	ShareProxyOnLAN  bool
}

// DirectEdgeRouteProfile returns a passthrough profile (no VPN).
// Source: MaybeEdgeScanner/EdgeRouteProfile.java direct()
func DirectEdgeRouteProfile() EdgeRouteProfile {
	return EdgeRouteProfile{
		Enabled:       false,
		RouteID:       "direct",
		RouteBinding:  "direct",
		ProtocolMode:  RouteProtocolDirect,
		RouteStrategy: RouteStrategyDirect,
		ProviderChain: RouteChainNone,
		DNSPolicy:     RouteDNSSystemDefault,
		Downstream:    RouteDownstreamScannerToRoute,
	}
}

// Route option constants (all values from MaybeEdgeScanner/RouteOptions.java)
const (
	// Protocol modes
	RouteProtocolExternalVPN          = "external_vpn"
	RouteProtocolLocalProxy           = "local_proxy"
	RouteProtocolWireGuard            = "wireguard"
	RouteProtocolOpenVPNUDP           = "openvpn_udp"
	RouteProtocolOpenVPNTCP           = "openvpn_tcp"
	RouteProtocolTCP                  = "tcp"
	RouteProtocolStealth              = "stealth"
	RouteProtocolWSTunnel             = "wstunnel"
	RouteProtocolIKEv2                = "ikev2"
	RouteProtocolTunnelCoreSupervised = "tunnel_core_supervised" // Psiphon
	RouteProtocolExternalVPNAPK       = "external_vpn_apk"
	RouteProtocolDirect               = "direct"

	// Auth modes
	RouteAuthNone          = "none"
	RouteAuthExternalApp   = "external_app"
	RouteAuthProfileRef    = "profile_ref"
	RouteAuthCredentialRef = "credential_ref"
	RouteAuthTokenRef      = "auth_token_ref"
	RouteAuthSSOExternal   = "sso_external"
	RouteAuthWsnetSession  = "wsnet_session_ref"
	RouteAuthPsiphonConfig = "config_ref"

	// DNS policies
	RouteDNSSystemDefault = "system_or_route_default"
	RouteDNSRemote        = "remote_dns"
	RouteDNSRoute         = "route_dns"
	RouteDNSControlD      = "ctrld"
	RouteDNSControlDAlt   = "control_d"
	RouteDNSROBERT        = "robert" // Windscribe ROBERT
	RouteDNSDoH           = "doh"
	RouteDNSDoT           = "dot"
	RouteDNSCustomRef     = "custom_dns_ref"
	RouteDNSNone          = "no_dns"

	// Split tunnel modes
	RouteSplitScannerOnly    = "scanner_app_only"
	RouteSplitInclude        = "include_targets"
	RouteSplitExclude        = "exclude_targets"
	RouteSplitExternalPolicy = "external_vpn_policy"
	RouteSplitDisabled       = "disabled"

	// Upstream modes
	RouteUpstreamNone            = "none"
	RouteUpstreamSystemProxy     = "system_proxy"
	RouteUpstreamProxyRef        = "proxy_ref"
	RouteUpstreamDirect          = "direct"
	RouteUpstreamProviderDefault = "provider_default"

	// Downstream modes
	RouteDownstreamScannerToRoute  = "scanner_to_route"
	RouteDownstreamLocalProxy      = "local_proxy_gateway"
	RouteDownstreamVPNInterface    = "vpn_interface"
	RouteDownstreamProviderDefault = "provider_default"

	// Route strategies
	RouteStrategyProviderDefault = "provider_default"
	RouteStrategyAuto            = "auto"
	RouteStrategyConduitFirst    = "conduit_first"
	RouteStrategyConduit         = "conduit"
	RouteStrategyCDNFronting     = "cdn_fronting"
	RouteStrategyDirect          = "direct"
	RouteStrategyProfileDefault  = "profile_default"

	// Conduit modes (Psiphon ShiroKhorshid)
	RouteConduitAuto          = "auto"
	RouteConduitShiroKhorshid = "shirokhorshid"
	RouteConduitPublic        = "public"

	// Provider chain modes
	RouteChainNone                 = "none"
	RouteChainPsiphonOverWindscribe = "psiphon_over_windscribe"
	RouteChainWindscribeOverPsiphon = "windscribe_over_psiphon"
	RouteChainProxyOverWindscribe  = "generic_proxy_over_windscribe"
	RouteChainWindscribeOverProxy  = "windscribe_over_generic_proxy"
)

// ---------------------------------------------------------------------------
// PsiphonTunnelSupervisor — Readiness states and notice parsing
// Source: MaybeEdgeScanner/PsiphonTunnelSupervisor.java
// ---------------------------------------------------------------------------

const (
	PsiphonStateNotChecked           = "not_checked"
	PsiphonStateStarting             = "starting"
	PsiphonStateProxyListening       = "proxy_listening"
	PsiphonStateFailed               = "failed"
	PsiphonStateAlreadyRunning       = "already_running"
	PsiphonStateNeedsConfigRef       = "needs_config_ref"
	PsiphonStateNeedsBinaryAndConfig = "needs_binary_and_config_ref"
	PsiphonStateNeedsTunnelCore      = "needs_tunnel_core_process"
	PsiphonStateExternalVPNObs       = "external_vpn_observation"
	PsiphonStateNeedsProfileOrPkg    = "needs_profile_or_package"
)

// PsiphonReadiness summarises the state of a Psiphon tunnel-core process.
// Source: MaybeEdgeScanner/PsiphonTunnelSupervisor.java Readiness
type PsiphonReadiness struct {
	RouteID          string
	Mode             string
	RouteStrategy    string
	ConduitMode      string
	FrontingPolicy   string // "custom_cdn_fronting" if fronting_ip_ref or fronting_sni set
	ProviderChain    string
	State            string
	PackageName      string
	LastNotice       string // truncated to 180 chars
	ErrorCode        string
	SOCKSPort        int
	HTTPProxyPort    int
	ConfigRefPresent bool
	ConfigReady      bool
	SessionReady     bool
	ProviderObserved bool
	ListenerReady    bool
	DialerReady      bool
	RouteUsed        bool
	ShareProxyOnLAN  bool
	BeastMode        bool
	Ready            bool
}

// ParsePsiphonNotice extracts port and state from a Psiphon tunnel-core notice line.
// Detects "ListeningSocksProxyPort" and "ListeningHttpProxyPort" in the notice text.
// Source: MaybeEdgeScanner/PsiphonTunnelSupervisor.java parseNotice() + extractPort()
func ParsePsiphonNotice(notice string) PsiphonReadiness {
	r := PsiphonReadiness{State: PsiphonStateStarting}
	if notice == "" {
		return r
	}
	if len(notice) > 180 {
		r.LastNotice = notice[:180]
	} else {
		r.LastNotice = notice
	}
	lower := strings.ToLower(notice)
	r.SOCKSPort = extractPortFromNotice(lower, "listeningsocksproxyport")
	r.HTTPProxyPort = extractPortFromNotice(lower, "listeninghttpproxyport")
	r.ListenerReady = r.SOCKSPort > 0 || r.HTTPProxyPort > 0
	r.ProviderObserved = r.ListenerReady
	r.DialerReady = r.ListenerReady
	r.Ready = r.ListenerReady
	if r.ListenerReady {
		r.State = PsiphonStateProxyListening
	}
	if strings.Contains(lower, "failed") || strings.Contains(lower, "error") {
		r.State = PsiphonStateFailed
		r.ErrorCode = "PSIPHON_NOTICE_ERROR"
		r.Ready = false
	}
	return r
}

func extractPortFromNotice(lower, key string) int {
	idx := strings.Index(lower, key)
	if idx < 0 {
		return 0
	}
	tail := lower[idx+len(key):]
	// Replace non-digits with spaces
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return ' '
	}, tail)
	fields := strings.Fields(digits)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0
	}
	return v
}

// ---------------------------------------------------------------------------
// Workflow profile name mapping
// Source: MaybeScanner/ScanWorkflowEngine.java profileName()
// ---------------------------------------------------------------------------

// WorkflowProfileName returns a human-readable name for the integer workflow profile.
// Profiles 0-3 match ScanProfileQuick..ScanProfileTunnel (step index, not ScanProfile type).
func WorkflowProfileName(profile int) string {
	switch profile {
	case 0:
		return "TCP"
	case 1:
		return "TLS"
	case 2:
		return "HTTP"
	case 3:
		return "Verify"
	}
	return "Profile " + strconv.Itoa(profile)
}

// DiagnosticTCPTargets are the well-known IP endpoints probed by NetworkDiagnosticsRunner.
// Source: MaybeScanner/NetworkDiagnosticsRunner.java
var DiagnosticTCPTargets = []struct {
	Name string
	IP   string
}{
	{"Cloudflare", "1.1.1.1"},
	{"Google DNS", "8.8.8.8"},
	{"Akamai DNS", "184.26.160.25"},
}

// DiagnosticDNSHosts are the DNS hostnames resolved to measure DNS latency.
// Source: MaybeScanner/NetworkDiagnosticsRunner.java
var DiagnosticDNSHosts = []string{
	"one.one.one.one",
	"dns.google",
	"aparat.com", // Iranian CDN — tests if Iranian DNS is accessible
}
