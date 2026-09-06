package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Post-refactor-235 planners capture second-order donor semantics that were
// hidden below the repository/module accounting completed in 234. Every
// planner is a deterministic transform over caller-supplied evidence. None of
// them starts a scanner, tunnel, DNS service, Tor client, proxy, or capture.

// Adaptive scan-load planning -------------------------------------------------
type ScanLoadPolicyRequest struct {
	CurrentConcurrency    int     `json:"current_concurrency"`
	MinConcurrency        int     `json:"min_concurrency"`
	MaxConcurrency        int     `json:"max_concurrency"`
	GatewayRTTMS          float64 `json:"gateway_rtt_ms"`
	BaselineRTTMS         float64 `json:"baseline_rtt_ms"`
	TimeoutRatePct        float64 `json:"timeout_rate_pct"`
	SampleCount           int     `json:"sample_count"`
	CandidateCount        int     `json:"candidate_count"`
	RequestedWorkers      int     `json:"requested_workers"`
	AllowUnmeasuredGrowth bool    `json:"allow_unmeasured_growth"`
}

type ScanLoadPolicyPlan struct {
	HealthState                                 string  `json:"health_state"`
	Action                                      string  `json:"action"`
	Reason                                      string  `json:"reason"`
	NextConcurrency                             int     `json:"next_concurrency"`
	WorkerCount                                 int     `json:"worker_count"`
	ChunkSizes                                  []int   `json:"chunk_sizes"`
	GatewayRatio                                float64 `json:"gateway_ratio"`
	TimeoutRatePct                              float64 `json:"timeout_rate_pct"`
	TimeoutInformationalOnly                    bool    `json:"timeout_informational_only"`
	StartsScan, MeasuresGateway, ChangesRuntime bool
	ReadOnly                                    bool     `json:"read_only"`
	Invariants                                  []string `json:"invariants"`
}

func BuildScanLoadPolicyPlan(r ScanLoadPolicyRequest) (ScanLoadPolicyPlan, error) {
	if r.MinConcurrency <= 0 || r.MaxConcurrency < r.MinConcurrency || r.MaxConcurrency > 100000 {
		return ScanLoadPolicyPlan{}, fmt.Errorf("invalid concurrency bounds")
	}
	if r.CurrentConcurrency < r.MinConcurrency || r.CurrentConcurrency > r.MaxConcurrency {
		return ScanLoadPolicyPlan{}, fmt.Errorf("current_concurrency outside bounds")
	}
	if r.TimeoutRatePct < 0 || r.TimeoutRatePct > 100 || r.SampleCount < 0 || r.SampleCount > 100000000 || r.CandidateCount < 0 || r.CandidateCount > 100000000 {
		return ScanLoadPolicyPlan{}, fmt.Errorf("invalid observation")
	}
	if r.GatewayRTTMS < 0 || r.BaselineRTTMS < 0 || r.GatewayRTTMS > 600000 || r.BaselineRTTMS > 600000 {
		return ScanLoadPolicyPlan{}, fmt.Errorf("invalid gateway RTT")
	}
	p := ScanLoadPolicyPlan{
		HealthState: "unknown", Action: "hold", NextConcurrency: r.CurrentConcurrency,
		TimeoutRatePct: r.TimeoutRatePct, TimeoutInformationalOnly: true, ReadOnly: true,
		Invariants: []string{
			"wild-scan timeout rate is informational and never independently proves congestion",
			"gateway RTT ratio is caller-supplied evidence; this planner never pings the gateway",
			"concurrency recommendations remain bounded by explicit minimum and maximum values",
			"resolver chunks are balanced round-robin by count only and do not start workers",
		},
	}
	if r.SampleCount < 20 {
		p.HealthState, p.Action, p.Reason = "insufficient-evidence", "hold", "fewer than 20 outcome samples"
	} else if r.BaselineRTTMS > 0 && r.GatewayRTTMS > 0 {
		p.GatewayRatio = r.GatewayRTTMS / r.BaselineRTTMS
		switch {
		case p.GatewayRatio >= 3.0:
			p.HealthState, p.Action, p.Reason = "congested", "backoff", "gateway RTT is at least 3x baseline"
			next := int(float64(r.CurrentConcurrency) * 0.70)
			if next < r.MinConcurrency {
				next = r.MinConcurrency
			}
			p.NextConcurrency = next
		case p.GatewayRatio >= 1.8:
			p.HealthState, p.Action, p.Reason = "degraded", "hold", "gateway RTT is at least 1.8x baseline"
		default:
			p.HealthState, p.Action, p.Reason = "healthy", "increase", "gateway RTT remains below warning ratio"
			next := r.CurrentConcurrency + 5
			if next > r.MaxConcurrency {
				next = r.MaxConcurrency
			}
			p.NextConcurrency = next
			if next == r.CurrentConcurrency {
				p.Action = "hold"
			}
		}
	} else if r.AllowUnmeasuredGrowth {
		p.HealthState, p.Action, p.Reason = "unmeasured", "increase", "gateway evidence unavailable; caller explicitly allows bounded growth"
		next := r.CurrentConcurrency + 5
		if next > r.MaxConcurrency {
			next = r.MaxConcurrency
		}
		p.NextConcurrency = next
		if next == r.CurrentConcurrency {
			p.Action = "hold"
		}
	} else {
		p.HealthState, p.Action, p.Reason = "unmeasured", "hold", "gateway evidence unavailable; conservative hold"
	}
	workers := r.RequestedWorkers
	if workers <= 0 {
		workers = p.NextConcurrency
	}
	if r.CandidateCount == 0 {
		workers = 0
	} else {
		if workers < 1 {
			workers = 1
		}
		if workers > r.CandidateCount {
			workers = r.CandidateCount
		}
	}
	p.WorkerCount = workers
	if workers > 0 {
		p.ChunkSizes = make([]int, workers)
		for i := 0; i < r.CandidateCount; i++ {
			p.ChunkSizes[i%workers]++
		}
	}
	return p, nil
}

// Mobile connection/readiness evidence ---------------------------------------
type MobileConnectionReadinessRequest struct {
	Phase            string   `json:"phase"`
	Completed        int      `json:"completed"`
	Total            int      `json:"total"`
	Valid            int      `json:"valid"`
	Rejected         int      `json:"rejected"`
	ActiveResolvers  []string `json:"active_resolvers"`
	StandbyResolvers []string `json:"standby_resolvers"`
	ValidResolvers   []string `json:"valid_resolvers"`
	RuntimeHealthy   bool     `json:"runtime_healthy"`
	WarmupCompleted  bool     `json:"warmup_completed"`
}

type MobileConnectionReadinessPlan struct {
	Phase                                           string   `json:"phase"`
	Percent                                         int      `json:"percent"`
	State                                           string   `json:"state"`
	Ready                                           bool     `json:"ready"`
	ActiveResolvers                                 []string `json:"active_resolvers"`
	StandbyResolvers                                []string `json:"standby_resolvers"`
	ValidResolvers                                  []string `json:"valid_resolvers"`
	ResolverCoveragePct                             float64  `json:"resolver_coverage_pct"`
	ParsesLogs, StartsRuntime, MutatesResolverState bool
	ReadOnly                                        bool     `json:"read_only"`
	Invariants                                      []string `json:"invariants"`
}

func cleanDistinctStrings(v []string, limit int) ([]string, error) {
	if len(v) > limit {
		return nil, fmt.Errorf("list exceeds %d", limit)
	}
	seen := map[string]bool{}
	out := []string{}
	for _, x := range v {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		if len(x) > 512 {
			return nil, fmt.Errorf("value too long")
		}
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out, nil
}

func BuildMobileConnectionReadinessPlan(r MobileConnectionReadinessRequest) (MobileConnectionReadinessPlan, error) {
	phase := strings.ToLower(strings.TrimSpace(r.Phase))
	allowed := map[string]bool{"starting": true, "mtu": true, "selecting": true, "session": true, "runtime": true, "connected": true, "failed": true, "stopped": true}
	if !allowed[phase] {
		return MobileConnectionReadinessPlan{}, fmt.Errorf("unsupported phase")
	}
	if r.Completed < 0 || r.Total < 0 || r.Valid < 0 || r.Rejected < 0 || (r.Total > 0 && r.Completed > r.Total) {
		return MobileConnectionReadinessPlan{}, fmt.Errorf("invalid progress counters")
	}
	a, err := cleanDistinctStrings(r.ActiveResolvers, 4096)
	if err != nil {
		return MobileConnectionReadinessPlan{}, err
	}
	s, err := cleanDistinctStrings(r.StandbyResolvers, 4096)
	if err != nil {
		return MobileConnectionReadinessPlan{}, err
	}
	v, err := cleanDistinctStrings(r.ValidResolvers, 4096)
	if err != nil {
		return MobileConnectionReadinessPlan{}, err
	}
	pct := 0
	switch phase {
	case "starting":
		pct = 5
	case "mtu":
		pct = 10
		if r.Total > 0 {
			pct = 10 + int((float64(r.Completed)/float64(r.Total))*70.0+0.5)
		}
	case "selecting":
		pct = 85
	case "session":
		pct = 90
	case "runtime":
		pct = 98
	case "connected":
		pct = 100
	case "failed", "stopped":
		pct = 0
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	coverage := 0.0
	if len(v)+r.Rejected > 0 {
		coverage = 100 * float64(len(v)) / float64(len(v)+r.Rejected)
	}
	ready := phase == "connected" && r.RuntimeHealthy && r.WarmupCompleted && len(v) > 0 && len(a) > 0
	state := phase
	if phase == "connected" && !ready {
		state = "connected-not-ready"
	}
	return MobileConnectionReadinessPlan{Phase: phase, Percent: pct, State: state, Ready: ready, ActiveResolvers: a, StandbyResolvers: s, ValidResolvers: v, ResolverCoveragePct: coverage, ReadOnly: true, Invariants: []string{"progress is derived from caller-supplied lifecycle evidence only", "connected is not equivalent to ready without healthy runtime, warmup, and valid active resolvers", "resolver lists are normalized and deduplicated without changing runtime state"}}, nil
}

// First-supported configuration fallback -------------------------------------
type ConfigFallbackCandidate struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
}
type ConfigFallbackRequest struct {
	Candidates []ConfigFallbackCandidate `json:"candidates"`
}
type ConfigFallbackPlan struct {
	SelectedID                                   string   `json:"selected_id,omitempty"`
	SelectedKind                                 string   `json:"selected_kind,omitempty"`
	SkippedUnsupported                           []string `json:"skipped_unsupported"`
	BlockingCandidate                            string   `json:"blocking_candidate,omitempty"`
	BlockingReason                               string   `json:"blocking_reason,omitempty"`
	Exhausted                                    bool     `json:"exhausted"`
	ParsesConfig, OpensTunnel, PersistsSelection bool
	ReadOnly                                     bool     `json:"read_only"`
	Invariants                                   []string `json:"invariants"`
}

func BuildConfigFallbackPlan(r ConfigFallbackRequest) (ConfigFallbackPlan, error) {
	if len(r.Candidates) == 0 {
		return ConfigFallbackPlan{}, fmt.Errorf("empty list of options")
	}
	if len(r.Candidates) > 128 {
		return ConfigFallbackPlan{}, fmt.Errorf("candidate count exceeds 128")
	}
	p := ConfigFallbackPlan{ReadOnly: true, Invariants: []string{"only explicit unsupported results are skipped", "the first supported candidate wins deterministically", "invalid or failed candidates stop fallback rather than being silently bypassed", "candidate evaluation is descriptive; no config is parsed or activated here"}}
	for i, c := range r.Candidates {
		id := strings.TrimSpace(c.ID)
		kind := strings.TrimSpace(c.Kind)
		st := strings.ToLower(strings.TrimSpace(c.Status))
		if id == "" {
			id = fmt.Sprintf("index:%d", i)
		}
		if len(id) > 128 || kind == "" || len(kind) > 128 {
			return ConfigFallbackPlan{}, fmt.Errorf("candidate %d invalid identity", i)
		}
		switch st {
		case "unsupported":
			p.SkippedUnsupported = append(p.SkippedUnsupported, id)
		case "supported":
			p.SelectedID, p.SelectedKind = id, kind
			return p, nil
		case "invalid", "error":
			p.BlockingCandidate, p.BlockingReason = id, st
			return p, nil
		default:
			return ConfigFallbackPlan{}, fmt.Errorf("candidate %d invalid status", i)
		}
	}
	p.Exhausted = true
	p.BlockingReason = "no supported option found"
	return p, nil
}

// DNS intercept / lazy base-session safety -----------------------------------
type DNSInterceptSafetyRequest struct {
	DestinationPort            int    `json:"destination_port"`
	DestinationIsLocalResolver bool   `json:"destination_is_local_resolver"`
	Transport                  string `json:"transport"`
	BaseSessionExists          bool   `json:"base_session_exists"`
	PacketBytes                int    `json:"packet_bytes"`
}
type DNSInterceptSafetyPlan struct {
	Intercept                                        bool   `json:"intercept"`
	ReturnTruncated                                  bool   `json:"return_truncated"`
	RequireTCPRetry                                  bool   `json:"require_tcp_retry"`
	CreateBaseSession                                bool   `json:"create_base_session"`
	ForwardToBase                                    bool   `json:"forward_to_base"`
	Reason                                           string `json:"reason"`
	MutatesPacket, CreatesSession, PerformsNetworkIO bool
	ReadOnly                                         bool     `json:"read_only"`
	Invariants                                       []string `json:"invariants"`
}

func BuildDNSInterceptSafetyPlan(r DNSInterceptSafetyRequest) (DNSInterceptSafetyPlan, error) {
	proto := strings.ToLower(strings.TrimSpace(r.Transport))
	if !(proto == "udp" || proto == "tcp") || r.DestinationPort < 1 || r.DestinationPort > 65535 || r.PacketBytes < 0 || r.PacketBytes > 65535 {
		return DNSInterceptSafetyPlan{}, fmt.Errorf("invalid DNS intercept observation")
	}
	p := DNSInterceptSafetyPlan{ReadOnly: true, Invariants: []string{"only UDP DNS directed at the configured local resolver is eligible for truncation", "DNS-only flows must not create an otherwise-unused base transport session", "non-DNS traffic remains delegated to the existing base owner", "the planner reports behavior but does not mutate packets or create sessions"}}
	if proto == "udp" && r.DestinationPort == 53 && r.DestinationIsLocalResolver {
		p.Intercept, p.ReturnTruncated, p.RequireTCPRetry = true, true, true
		p.Reason = "local UDP DNS should receive a truncated response and retry over TCP"
		return p, nil
	}
	p.ForwardToBase = true
	p.CreateBaseSession = !r.BaseSessionExists
	p.Reason = "traffic is outside local UDP DNS interception and remains on the base path"
	return p, nil
}

// Tor consensus, family, diversity and exit-policy evidence ------------------
type TorConsensusRelayObservation struct {
	Fingerprint      string   `json:"fingerprint"`
	IPv4             string   `json:"ipv4"`
	Flags            []string `json:"flags"`
	Family           []string `json:"family"`
	BandwidthWeight  int      `json:"bandwidth_weight"`
	ExitAllowedPorts []int    `json:"exit_allowed_ports"`
}
type TorConsensusEvidenceRequest struct {
	NowUnix        int64                          `json:"now_unix"`
	ValidAfterUnix int64                          `json:"valid_after_unix"`
	FreshUntilUnix int64                          `json:"fresh_until_unix"`
	Relays         []TorConsensusRelayObservation `json:"relays"`
}
type TorConsensusEvidencePlan struct {
	ConsensusState                                                   string      `json:"consensus_state"`
	Accepted                                                         int         `json:"accepted"`
	Rejected                                                         int         `json:"rejected"`
	RunningValid                                                     int         `json:"running_valid"`
	BadExit                                                          int         `json:"bad_exit"`
	FamilyAsymmetries                                                []string    `json:"family_asymmetries"`
	SharedIPv4Prefix16                                               []string    `json:"shared_ipv4_prefix16"`
	ExitPorts                                                        map[int]int `json:"exit_ports"`
	TotalBandwidthWeight                                             int64       `json:"total_bandwidth_weight"`
	FetchesConsensus, SelectsCircuit, ControlsTor, PerformsNetworkIO bool
	ReadOnly                                                         bool     `json:"read_only"`
	Invariants                                                       []string `json:"invariants"`
}

func canonicalFP(v string) (string, bool) {
	v = strings.ToUpper(strings.TrimSpace(v))
	if len(v) != 40 {
		return "", false
	}
	_, e := hex.DecodeString(v)
	return v, e == nil
}
func BuildTorConsensusEvidencePlan(r TorConsensusEvidenceRequest) (TorConsensusEvidencePlan, error) {
	if len(r.Relays) > 20000 {
		return TorConsensusEvidencePlan{}, fmt.Errorf("relay count exceeds 20000")
	}
	if r.NowUnix < 0 || r.ValidAfterUnix < 0 || r.FreshUntilUnix < 0 || r.FreshUntilUnix < r.ValidAfterUnix {
		return TorConsensusEvidencePlan{}, fmt.Errorf("invalid consensus timestamps")
	}
	p := TorConsensusEvidencePlan{ExitPorts: map[int]int{}, ReadOnly: true, Invariants: []string{"consensus freshness is evidence, never circuit authority", "family relationships are checked for reciprocity rather than trusted by declaration", "shared address prefixes are surfaced as diversity risk only", "exit-policy ports and bandwidth weights remain descriptive inputs"}}
	switch {
	case r.NowUnix < r.ValidAfterUnix:
		p.ConsensusState = "not-yet-valid"
	case r.NowUnix > r.FreshUntilUnix:
		p.ConsensusState = "stale"
	default:
		p.ConsensusState = "fresh"
	}
	type accepted struct {
		fp, ip string
		flags  map[string]bool
		family []string
	}
	rel := map[string]accepted{}
	prefixes := map[string][]string{}
	allowFlag := map[string]bool{"running": true, "valid": true, "exit": true, "guard": true, "fast": true, "stable": true, "hsdir": true, "badexit": true, "authority": true, "v2dir": true}
	for _, o := range r.Relays {
		fp, ok := canonicalFP(o.Fingerprint)
		if !ok || o.BandwidthWeight < 0 || o.BandwidthWeight > 100000000 {
			p.Rejected++
			continue
		}
		ip := strings.TrimSpace(o.IPv4)
		if ip != "" {
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.To4() == nil {
				p.Rejected++
				continue
			}
			v4 := parsed.To4()
			prefix := fmt.Sprintf("%d.%d.0.0/16", v4[0], v4[1])
			prefixes[prefix] = append(prefixes[prefix], fp)
		}
		fs := map[string]bool{}
		bad := false
		for _, f := range o.Flags {
			f = strings.ToLower(strings.TrimSpace(f))
			if !allowFlag[f] {
				bad = true
				break
			}
			fs[f] = true
		}
		if bad {
			p.Rejected++
			continue
		}
		fam := []string{}
		for _, x := range o.Family {
			if cf, ok := canonicalFP(strings.TrimPrefix(strings.TrimSpace(x), "$")); ok && cf != fp {
				fam = append(fam, cf)
			}
		}
		sort.Strings(fam)
		fam = dedupeSorted(fam)
		portsSeen := map[int]bool{}
		for _, port := range o.ExitAllowedPorts {
			if port < 1 || port > 65535 {
				bad = true
				break
			}
			if !portsSeen[port] {
				portsSeen[port] = true
				p.ExitPorts[port]++
			}
		}
		if bad {
			p.Rejected++
			continue
		}
		p.Accepted++
		if fs["running"] && fs["valid"] {
			p.RunningValid++
		}
		if fs["badexit"] {
			p.BadExit++
		}
		p.TotalBandwidthWeight += int64(o.BandwidthWeight)
		rel[fp] = accepted{fp: fp, ip: ip, flags: fs, family: fam}
	}
	for fp, o := range rel {
		for _, member := range o.family {
			m, ok := rel[member]
			if !ok {
				p.FamilyAsymmetries = append(p.FamilyAsymmetries, fp+"->"+member+":missing")
				continue
			}
			found := false
			for _, back := range m.family {
				if back == fp {
					found = true
					break
				}
			}
			if !found {
				p.FamilyAsymmetries = append(p.FamilyAsymmetries, fp+"->"+member+":not-reciprocal")
			}
		}
	}
	sort.Strings(p.FamilyAsymmetries)
	for prefix, fps := range prefixes {
		if len(fps) > 1 {
			sort.Strings(fps)
			p.SharedIPv4Prefix16 = append(p.SharedIPv4Prefix16, prefix+"="+strings.Join(fps, ","))
		}
	}
	sort.Strings(p.SharedIPv4Prefix16)
	return p, nil
}
func normalizeSchemaKeys(values []string, omitSensitiveHeaders bool) ([]string, int) {
	seen := map[string]bool{}
	out := []string{}
	omitted := 0
	for _, raw := range values {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" || len(v) > 128 || strings.ContainsAny(v, "\r\n") {
			continue
		}
		if omitSensitiveHeaders {
			switch v {
			case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key":
				omitted++
				continue
			}
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out, omitted
}

func dedupeSorted(v []string) []string {
	if len(v) == 0 {
		return v
	}
	out := v[:1]
	for _, x := range v[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// DNSCrypt resolver/relay source topology ------------------------------------
type DNSCryptTopologyResolver struct {
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`
	SourceSigned   bool   `json:"source_signed"`
	SourceAgeHours int    `json:"source_age_hours"`
	RequiresRelay  bool   `json:"requires_relay"`
}
type DNSCryptTopologyRelay struct {
	Name           string   `json:"name"`
	Protocols      []string `json:"protocols"`
	SourceSigned   bool     `json:"source_signed"`
	SourceAgeHours int      `json:"source_age_hours"`
	Available      bool     `json:"available"`
}
type DNSCryptTopologyRequest struct {
	MaxSourceAgeHours int                        `json:"max_source_age_hours"`
	Resolvers         []DNSCryptTopologyResolver `json:"resolvers"`
	Relays            []DNSCryptTopologyRelay    `json:"relays"`
}
type DNSCryptPairing struct {
	Resolver string `json:"resolver"`
	Relay    string `json:"relay"`
	Protocol string `json:"protocol"`
}
type DNSCryptTopologyPlan struct {
	EligibleResolvers                                                []string          `json:"eligible_resolvers"`
	Rejected                                                         map[string]string `json:"rejected"`
	Pairings                                                         []DNSCryptPairing `json:"pairings"`
	FetchesSources, StartsProxy, ChangesSystemDNS, PerformsNetworkIO bool
	ReadOnly                                                         bool     `json:"read_only"`
	Invariants                                                       []string `json:"invariants"`
}

func BuildDNSCryptTopologyPlan(r DNSCryptTopologyRequest) (DNSCryptTopologyPlan, error) {
	if len(r.Resolvers) > 4096 || len(r.Relays) > 4096 {
		return DNSCryptTopologyPlan{}, fmt.Errorf("topology input exceeds 4096")
	}
	maxAge := r.MaxSourceAgeHours
	if maxAge == 0 {
		maxAge = 168
	}
	if maxAge < 1 || maxAge > 24*365 {
		return DNSCryptTopologyPlan{}, fmt.Errorf("max_source_age_hours out of range")
	}
	p := DNSCryptTopologyPlan{Rejected: map[string]string{}, ReadOnly: true, Invariants: []string{"unsigned or stale source metadata is not silently promoted", "relay-required resolvers are eligible only when at least one compatible trusted relay exists", "resolver and relay sources are never downloaded by this planner", "pairing does not start dnscrypt-proxy or change system DNS"}}
	type relay struct {
		name string
		prot map[string]bool
	}
	eligibleRelays := []relay{}
	for i, x := range r.Relays {
		name := strings.TrimSpace(x.Name)
		key := name
		if key == "" {
			key = fmt.Sprintf("relay:%d", i)
		}
		if name == "" || len(name) > 128 || !x.SourceSigned || x.SourceAgeHours < 0 || x.SourceAgeHours > maxAge || !x.Available {
			p.Rejected[key] = "relay source unavailable, unsigned, stale, or invalid"
			continue
		}
		pm := map[string]bool{}
		for _, pr := range x.Protocols {
			pr = strings.ToLower(strings.TrimSpace(pr))
			if pr == "dnscrypt" || pr == "doh" || pr == "odoh" {
				pm[pr] = true
			}
		}
		if len(pm) == 0 {
			p.Rejected[key] = "relay has no supported protocol"
			continue
		}
		eligibleRelays = append(eligibleRelays, relay{name: name, prot: pm})
	}
	for i, x := range r.Resolvers {
		name := strings.TrimSpace(x.Name)
		key := name
		if key == "" {
			key = fmt.Sprintf("resolver:%d", i)
		}
		proto := strings.ToLower(strings.TrimSpace(x.Protocol))
		if name == "" || len(name) > 128 || !(proto == "dnscrypt" || proto == "doh" || proto == "dot" || proto == "odoh") || !x.SourceSigned || x.SourceAgeHours < 0 || x.SourceAgeHours > maxAge {
			p.Rejected[key] = "resolver source unsigned, stale, or invalid"
			continue
		}
		matches := 0
		if x.RequiresRelay {
			for _, rr := range eligibleRelays {
				if rr.prot[proto] {
					p.Pairings = append(p.Pairings, DNSCryptPairing{Resolver: name, Relay: rr.name, Protocol: proto})
					matches++
				}
			}
			if matches == 0 {
				p.Rejected[key] = "no compatible trusted relay"
				continue
			}
		}
		p.EligibleResolvers = append(p.EligibleResolvers, name)
	}
	sort.Strings(p.EligibleResolvers)
	sort.Slice(p.Pairings, func(i, j int) bool {
		if p.Pairings[i].Resolver == p.Pairings[j].Resolver {
			return p.Pairings[i].Relay < p.Pairings[j].Relay
		}
		return p.Pairings[i].Resolver < p.Pairings[j].Resolver
	})
	return p, nil
}

// Evidence receipt topology ---------------------------------------------------
type EvidenceReceiptObservation struct {
	ID              string `json:"id"`
	SHA256          string `json:"sha256"`
	ParentSHA256    string `json:"parent_sha256"`
	SignatureStatus string `json:"signature_status"`
	TimestampStatus string `json:"timestamp_status"`
	MetadataConsent bool   `json:"metadata_consent"`
}
type EvidenceReceiptRequest struct {
	Artifacts []EvidenceReceiptObservation `json:"artifacts"`
}
type EvidenceReceiptTopologyPlan struct {
	Roots                                                             []string `json:"roots"`
	Leaves                                                            []string `json:"leaves"`
	MissingParents                                                    []string `json:"missing_parents"`
	Cycles                                                            []string `json:"cycles"`
	FailedEvidence                                                    []string `json:"failed_evidence"`
	UnknownEvidence                                                   []string `json:"unknown_evidence"`
	MetadataWithoutConsent                                            []string `json:"metadata_without_consent"`
	Complete                                                          bool     `json:"complete"`
	TopologySHA256                                                    string   `json:"topology_sha256"`
	ReadsFiles, SignsArtifacts, VerifiesExternally, PerformsNetworkIO bool
	ReadOnly                                                          bool     `json:"read_only"`
	Invariants                                                        []string `json:"invariants"`
}

func BuildEvidenceReceiptTopologyPlan(r EvidenceReceiptRequest) (EvidenceReceiptTopologyPlan, error) {
	if len(r.Artifacts) > 4096 {
		return EvidenceReceiptTopologyPlan{}, fmt.Errorf("artifact count exceeds 4096")
	}
	p := EvidenceReceiptTopologyPlan{ReadOnly: true, Invariants: []string{"receipt topology is derived from caller-supplied digests only", "missing parents and cycles are explicit failures", "unknown signature or timestamp status never counts as complete", "metadata consent is evaluated separately from cryptographic validity"}}
	byDigest := map[string]EvidenceReceiptObservation{}
	idByDigest := map[string]string{}
	children := map[string]int{}
	cov := []string{}
	for i, o := range r.Artifacts {
		id := strings.TrimSpace(o.ID)
		h := strings.ToLower(strings.TrimSpace(o.SHA256))
		parent := strings.ToLower(strings.TrimSpace(o.ParentSHA256))
		sig := strings.ToLower(strings.TrimSpace(o.SignatureStatus))
		ts := strings.ToLower(strings.TrimSpace(o.TimestampStatus))
		if id == "" || len(id) > 128 || len(h) != 64 {
			return EvidenceReceiptTopologyPlan{}, fmt.Errorf("artifact %d invalid identity", i)
		}
		if _, e := hex.DecodeString(h); e != nil {
			return EvidenceReceiptTopologyPlan{}, fmt.Errorf("artifact %d invalid sha256", i)
		}
		if parent != "" {
			if len(parent) != 64 {
				return EvidenceReceiptTopologyPlan{}, fmt.Errorf("artifact %d invalid parent", i)
			}
			if _, e := hex.DecodeString(parent); e != nil {
				return EvidenceReceiptTopologyPlan{}, fmt.Errorf("artifact %d invalid parent", i)
			}
		}
		if _, dup := byDigest[h]; dup {
			return EvidenceReceiptTopologyPlan{}, fmt.Errorf("duplicate artifact digest")
		}
		if !(sig == "pass" || sig == "fail" || sig == "unknown" || sig == "not-applicable") || !(ts == "pass" || ts == "fail" || ts == "unknown" || ts == "not-applicable") {
			return EvidenceReceiptTopologyPlan{}, fmt.Errorf("artifact %d invalid evidence status", i)
		}
		o.ID = id
		o.SHA256 = h
		o.ParentSHA256 = parent
		o.SignatureStatus = sig
		o.TimestampStatus = ts
		byDigest[h] = o
		idByDigest[h] = id
		if parent != "" {
			children[parent]++
		}
		if sig == "fail" || ts == "fail" {
			p.FailedEvidence = append(p.FailedEvidence, id)
		} else if sig == "unknown" || ts == "unknown" {
			p.UnknownEvidence = append(p.UnknownEvidence, id)
		}
		if !o.MetadataConsent {
			p.MetadataWithoutConsent = append(p.MetadataWithoutConsent, id)
		}
		cov = append(cov, id+"|"+h+"|"+parent+"|"+sig+"|"+ts+fmt.Sprintf("|%t", o.MetadataConsent))
	}
	for h, o := range byDigest {
		if o.ParentSHA256 == "" {
			p.Roots = append(p.Roots, o.ID)
		} else if _, ok := byDigest[o.ParentSHA256]; !ok {
			p.MissingParents = append(p.MissingParents, o.ID+"->"+o.ParentSHA256)
		}
		if children[h] == 0 {
			p.Leaves = append(p.Leaves, o.ID)
		}
	}
	// Parent pointers form a functional graph; detect cycles deterministically.
	for start := range byDigest {
		seen := map[string]int{}
		cur := start
		step := 0
		for cur != "" {
			if at, ok := seen[cur]; ok {
				cycle := []string{}
				x := cur
				for {
					cycle = append(cycle, idByDigest[x])
					x = byDigest[x].ParentSHA256
					if x == cur || x == "" {
						break
					}
				}
				sort.Strings(cycle)
				p.Cycles = append(p.Cycles, strings.Join(cycle, "->"))
				_ = at
				break
			}
			seen[cur] = step
			step++
			o, ok := byDigest[cur]
			if !ok {
				break
			}
			cur = o.ParentSHA256
		}
	}
	sort.Strings(p.Roots)
	sort.Strings(p.Leaves)
	sort.Strings(p.MissingParents)
	sort.Strings(p.FailedEvidence)
	sort.Strings(p.UnknownEvidence)
	sort.Strings(p.MetadataWithoutConsent)
	sort.Strings(p.Cycles)
	p.Cycles = dedupeSorted(p.Cycles)
	sort.Strings(cov)
	sum := sha256.Sum256([]byte(strings.Join(cov, "\n")))
	p.TopologySHA256 = hex.EncodeToString(sum[:])
	p.Complete = len(p.MissingParents) == 0 && len(p.Cycles) == 0 && len(p.FailedEvidence) == 0 && len(p.UnknownEvidence) == 0
	return p, nil
}

// DNS filter preset composition ----------------------------------------------
type DNSFilterListObservation struct {
	Name            string `json:"name"`
	Category        string `json:"category"`
	Format          string `json:"format"`
	Entries         int    `json:"entries"`
	AllowExceptions bool   `json:"allow_exceptions"`
}
type DNSFilterPresetRequest struct {
	Intent string                     `json:"intent"`
	Lists  []DNSFilterListObservation `json:"lists"`
}
type DNSFilterPresetPlan struct {
	Intent                                      string            `json:"intent"`
	Selected                                    []string          `json:"selected"`
	Optional                                    []string          `json:"optional"`
	Rejected                                    map[string]string `json:"rejected"`
	TotalEntries                                int64             `json:"total_entries"`
	AppliesBlocking, FetchesLists, WritesConfig bool
	ReadOnly                                    bool     `json:"read_only"`
	Invariants                                  []string `json:"invariants"`
}

func BuildDNSFilterPresetPlan(r DNSFilterPresetRequest) (DNSFilterPresetPlan, error) {
	intent := strings.ToLower(strings.TrimSpace(r.Intent))
	allowIntent := map[string]bool{"balanced": true, "privacy": true, "security": true, "family": true, "anti-bypass": true}
	if !allowIntent[intent] {
		return DNSFilterPresetPlan{}, fmt.Errorf("unsupported intent")
	}
	if len(r.Lists) > 2048 {
		return DNSFilterPresetPlan{}, fmt.Errorf("list count exceeds 2048")
	}
	p := DNSFilterPresetPlan{Intent: intent, Rejected: map[string]string{}, ReadOnly: true, Invariants: []string{"preset composition selects caller-supplied list identities only", "category intent never authorizes remote feed retrieval or blocking", "allow/exception-bearing lists remain explicit rather than silently merged", "selected list names are deterministic and sorted"}}
	wanted := map[string]map[string]bool{"balanced": {"ads": true, "tracking": true, "malware": true, "phishing": true}, "privacy": {"tracking": true, "telemetry": true, "social": true, "native": true}, "security": {"malware": true, "phishing": true, "badware": true, "threat": true, "tif": true}, "family": {"adult": true, "nsfw": true, "gambling": true, "nosafesearch": true}, "anti-bypass": {"doh": true, "vpn": true, "proxy": true, "dyndns": true, "rebind": true}}[intent]
	seen := map[string]bool{}
	for i, o := range r.Lists {
		name := strings.TrimSpace(o.Name)
		cat := strings.ToLower(strings.TrimSpace(o.Category))
		format := strings.ToLower(strings.TrimSpace(o.Format))
		key := name
		if key == "" {
			key = fmt.Sprintf("index:%d", i)
		}
		if name == "" || len(name) > 160 || cat == "" || len(cat) > 64 || o.Entries < 0 || o.Entries > 100000000 || format == "" {
			p.Rejected[key] = "invalid list metadata"
			continue
		}
		if seen[name] {
			p.Rejected[key] = "duplicate list name"
			continue
		}
		seen[name] = true
		match := false
		for token := range wanted {
			if strings.Contains(cat, token) || strings.Contains(strings.ToLower(name), token) {
				match = true
				break
			}
		}
		if match {
			p.Selected = append(p.Selected, name)
			p.TotalEntries += int64(o.Entries)
		} else if o.AllowExceptions {
			p.Optional = append(p.Optional, name)
		}
	}
	sort.Strings(p.Selected)
	sort.Strings(p.Optional)
	return p, nil
}

// Network evidence bundle ----------------------------------------------------
// NetworkEvidenceBundleRequest composes independently bounded planners without
// introducing a new runtime or write owner. Nil components are simply omitted.
type NetworkEvidenceBundleRequest struct {
	ScanLoad     *ScanLoadPolicyRequest            `json:"scan_load,omitempty"`
	Mobile       *MobileConnectionReadinessRequest `json:"mobile,omitempty"`
	DNSIntercept *DNSInterceptSafetyRequest        `json:"dns_intercept,omitempty"`
	TorConsensus *TorConsensusEvidenceRequest      `json:"tor_consensus,omitempty"`
	DNSCrypt     *DNSCryptTopologyRequest          `json:"dnscrypt,omitempty"`
	DNSFilter    *DNSFilterPresetRequest           `json:"dns_filter,omitempty"`
	Evidence     *EvidenceReceiptRequest           `json:"evidence,omitempty"`
}

type NetworkEvidenceBundlePlan struct {
	Status       string                         `json:"status"`
	Selected     []string                       `json:"selected"`
	Warnings     []string                       `json:"warnings"`
	ScanLoad     *ScanLoadPolicyPlan            `json:"scan_load,omitempty"`
	Mobile       *MobileConnectionReadinessPlan `json:"mobile,omitempty"`
	DNSIntercept *DNSInterceptSafetyPlan        `json:"dns_intercept,omitempty"`
	TorConsensus *TorConsensusEvidencePlan      `json:"tor_consensus,omitempty"`
	DNSCrypt     *DNSCryptTopologyPlan          `json:"dnscrypt,omitempty"`
	DNSFilter    *DNSFilterPresetPlan           `json:"dns_filter,omitempty"`
	Evidence     *EvidenceReceiptTopologyPlan   `json:"evidence,omitempty"`
	ReadOnly     bool                           `json:"read_only"`
	Invariants   []string                       `json:"invariants"`
}

func BuildNetworkEvidenceBundlePlan(r NetworkEvidenceBundleRequest) (NetworkEvidenceBundlePlan, error) {
	p := NetworkEvidenceBundlePlan{Status: "ready", ReadOnly: true, Invariants: []string{
		"bundle status is derived only from selected read-only child plans",
		"a child warning or incomplete state can degrade the aggregate but can never grant authority",
		"no scanner, DNS service, Tor controller, tunnel, proxy, packet mutator, or evidence signer is started",
	}}
	if r.ScanLoad != nil {
		v, err := BuildScanLoadPolicyPlan(*r.ScanLoad)
		if err != nil {
			return p, fmt.Errorf("scan_load: %w", err)
		}
		p.ScanLoad = &v
		p.Selected = append(p.Selected, "scan-load")
		if v.HealthState == "critical" || v.HealthState == "degraded" || v.HealthState == "unknown" {
			p.Status = "degraded"
			p.Warnings = append(p.Warnings, "scan load evidence is "+v.HealthState)
		}
	}
	if r.Mobile != nil {
		v, err := BuildMobileConnectionReadinessPlan(*r.Mobile)
		if err != nil {
			return p, fmt.Errorf("mobile: %w", err)
		}
		p.Mobile = &v
		p.Selected = append(p.Selected, "mobile-readiness")
		if !v.Ready {
			p.Status = "degraded"
			p.Warnings = append(p.Warnings, "mobile connection is not fully ready")
		}
	}
	if r.DNSIntercept != nil {
		v, err := BuildDNSInterceptSafetyPlan(*r.DNSIntercept)
		if err != nil {
			return p, fmt.Errorf("dns_intercept: %w", err)
		}
		p.DNSIntercept = &v
		p.Selected = append(p.Selected, "dns-intercept")
	}
	if r.TorConsensus != nil {
		v, err := BuildTorConsensusEvidencePlan(*r.TorConsensus)
		if err != nil {
			return p, fmt.Errorf("tor_consensus: %w", err)
		}
		p.TorConsensus = &v
		p.Selected = append(p.Selected, "tor-consensus")
		if v.ConsensusState != "fresh" || v.Rejected > 0 || len(v.FamilyAsymmetries) > 0 || len(v.SharedIPv4Prefix16) > 0 {
			p.Status = "degraded"
			p.Warnings = append(p.Warnings, "Tor consensus evidence is not fully healthy")
		}
	}
	if r.DNSCrypt != nil {
		v, err := BuildDNSCryptTopologyPlan(*r.DNSCrypt)
		if err != nil {
			return p, fmt.Errorf("dnscrypt: %w", err)
		}
		p.DNSCrypt = &v
		p.Selected = append(p.Selected, "dnscrypt-topology")
		if len(v.Rejected) > 0 {
			p.Status = "degraded"
			p.Warnings = append(p.Warnings, "DNSCrypt topology contains rejected entries")
		}
	}
	if r.DNSFilter != nil {
		v, err := BuildDNSFilterPresetPlan(*r.DNSFilter)
		if err != nil {
			return p, fmt.Errorf("dns_filter: %w", err)
		}
		p.DNSFilter = &v
		p.Selected = append(p.Selected, "dns-filter-preset")
	}
	if r.Evidence != nil {
		v, err := BuildEvidenceReceiptTopologyPlan(*r.Evidence)
		if err != nil {
			return p, fmt.Errorf("evidence: %w", err)
		}
		p.Evidence = &v
		p.Selected = append(p.Selected, "evidence-receipts")
		if !v.Complete {
			p.Status = "degraded"
			p.Warnings = append(p.Warnings, "evidence receipt topology is incomplete")
		}
	}
	if len(p.Selected) == 0 {
		return p, fmt.Errorf("at least one bundle component is required")
	}
	p.Selected = dedupeSorted(p.Selected)
	p.Warnings = dedupeSorted(p.Warnings)
	return p, nil
}
