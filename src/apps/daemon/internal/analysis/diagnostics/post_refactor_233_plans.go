package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Post-refactor-233 planners are deliberately read-only. They normalize or
// evaluate caller-supplied evidence without fetching subscriptions, opening
// sockets, controlling Tor, changing host settings, or installing rules.

// DNS subscription refinement -------------------------------------------------

type DNSRefinerObservation struct {
	SourceKey    string `json:"source_key"`
	Scheme       string `json:"scheme"`
	NameServer   string `json:"name_server,omitempty"`
	Address      string `json:"address,omitempty"`
	HasPublicKey bool   `json:"has_public_key,omitempty"`
	HasUser      bool   `json:"has_user,omitempty"`
	HasPassword  bool   `json:"has_password,omitempty"`
}

type DNSRefinerPlanRequest struct {
	AllowedSchemes []string                `json:"allowed_schemes"`
	OutputOrder    string                  `json:"output_order"`
	SelectionSeed  string                  `json:"selection_seed,omitempty"`
	Observations   []DNSRefinerObservation `json:"observations"`
}

type DNSRefinerDecision struct {
	SourceKey         string `json:"source_key"`
	Scheme            string `json:"scheme"`
	NameServer        string `json:"name_server,omitempty"`
	Address           string `json:"address,omitempty"`
	CredentialFields  int    `json:"credential_fields"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

type DNSRefinerPlan struct {
	Accepted             []DNSRefinerDecision `json:"accepted"`
	Rejected             map[string]string    `json:"rejected"`
	AllowedSchemes       []string             `json:"allowed_schemes"`
	OutputOrder          string               `json:"output_order"`
	FetchesSubscriptions bool                 `json:"fetches_subscriptions"`
	WritesExports        bool                 `json:"writes_exports"`
	RevealsCredentials   bool                 `json:"reveals_credentials"`
	PerformsNetworkIO    bool                 `json:"performs_network_io"`
	ReadOnly             bool                 `json:"read_only"`
	Invariants           []string             `json:"invariants"`
}

func normalizeDNSScheme(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "dns", "slipnet", "dnstt":
		return v
	}
	return ""
}

func BuildDNSRefinerPlan(req DNSRefinerPlanRequest) (DNSRefinerPlan, error) {
	if len(req.Observations) > 4096 {
		return DNSRefinerPlan{}, fmt.Errorf("observation count exceeds 4096")
	}
	allowed := map[string]bool{}
	for _, raw := range req.AllowedSchemes {
		s := normalizeDNSScheme(raw)
		if s == "" {
			return DNSRefinerPlan{}, fmt.Errorf("unsupported DNS scheme %q", raw)
		}
		allowed[s] = true
	}
	if len(allowed) == 0 {
		allowed["dns"] = true
		allowed["slipnet"] = true
		allowed["dnstt"] = true
	}
	order := strings.ToUpper(strings.TrimSpace(req.OutputOrder))
	if order == "" {
		order = "ASC"
	}
	if order != "ASC" && order != "DESC" && order != "HASH" {
		return DNSRefinerPlan{}, fmt.Errorf("output_order must be ASC, DESC, or HASH")
	}
	plan := DNSRefinerPlan{Rejected: map[string]string{}, OutputOrder: order, ReadOnly: true, Invariants: []string{
		"normalization uses only caller-supplied observations",
		"credential presence is counted but credential values are never accepted or emitted",
		"no subscription is fetched and no export directory is written",
	}}
	for s := range allowed {
		plan.AllowedSchemes = append(plan.AllowedSchemes, s)
	}
	sort.Strings(plan.AllowedSchemes)
	seen := map[string]bool{}
	for i, o := range req.Observations {
		key := strings.TrimSpace(o.SourceKey)
		if key == "" || len(key) > 96 {
			plan.Rejected[fmt.Sprintf("index:%d", i)] = "invalid source_key"
			continue
		}
		s := normalizeDNSScheme(o.Scheme)
		if s == "" || !allowed[s] {
			plan.Rejected[key] = "scheme not admitted"
			continue
		}
		ns := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(o.NameServer)), ".")
		addr := strings.TrimSpace(o.Address)
		if ns == "" && addr == "" {
			plan.Rejected[key] = "missing nameserver/address evidence"
			continue
		}
		dedupe := strings.Join([]string{key, s, ns, addr}, "|")
		if seen[dedupe] {
			plan.Rejected[key] = "duplicate observation"
			continue
		}
		seen[dedupe] = true
		creds := 0
		if o.HasPublicKey {
			creds++
		}
		if o.HasUser {
			creds++
		}
		if o.HasPassword {
			creds++
		}
		sum := sha256.Sum256([]byte(dedupe + "|" + req.SelectionSeed))
		plan.Accepted = append(plan.Accepted, DNSRefinerDecision{SourceKey: key, Scheme: s, NameServer: ns, Address: addr, CredentialFields: creds, FingerprintSHA256: hex.EncodeToString(sum[:])})
	}
	sort.SliceStable(plan.Accepted, func(i, j int) bool {
		a, b := plan.Accepted[i], plan.Accepted[j]
		if order == "HASH" {
			return a.FingerprintSHA256 < b.FingerprintSHA256
		}
		less := a.SourceKey < b.SourceKey
		if a.SourceKey == b.SourceKey {
			less = a.Scheme < b.Scheme
		}
		if order == "DESC" {
			return !less && (a.SourceKey != b.SourceKey || a.Scheme != b.Scheme)
		}
		return less
	})
	return plan, nil
}

// HTTPS Everywhere style rule corpus audit -----------------------------------

type HTTPSUpgradeRuleObservation struct {
	Name       string   `json:"name"`
	Targets    []string `json:"targets"`
	Exclusions []string `json:"exclusions,omitempty"`
	Disabled   bool     `json:"disabled,omitempty"`
}
type HTTPSUpgradeRulesetPlanRequest struct {
	Rules []HTTPSUpgradeRuleObservation `json:"rules"`
}
type HTTPSUpgradeRulesetPlan struct {
	RuleCount            int      `json:"rule_count"`
	TargetCount          int      `json:"target_count"`
	DisabledRules        int      `json:"disabled_rules"`
	DuplicateTargets     []string `json:"duplicate_targets"`
	InvalidTargets       []string `json:"invalid_targets"`
	CoverageSHA256       string   `json:"coverage_sha256"`
	InstallsBrowserRules bool     `json:"installs_browser_rules"`
	RedirectsRequests    bool     `json:"redirects_requests"`
	ExecutesRegex        bool     `json:"executes_regex"`
	PerformsNetworkIO    bool     `json:"performs_network_io"`
	ReadOnly             bool     `json:"read_only"`
	Invariants           []string `json:"invariants"`
}

func validUpgradeTarget(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" || len(v) > 253 || strings.ContainsAny(v, " /:@?#") {
		return false
	}
	if strings.HasPrefix(v, "*.") {
		v = strings.TrimPrefix(v, "*.")
	}
	if strings.HasPrefix(v, ".") || strings.HasSuffix(v, ".") || !strings.Contains(v, ".") {
		return false
	}
	for _, p := range strings.Split(v, ".") {
		if p == "" || len(p) > 63 {
			return false
		}
		for _, r := range p {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func BuildHTTPSUpgradeRulesetPlan(req HTTPSUpgradeRulesetPlanRequest) (HTTPSUpgradeRulesetPlan, error) {
	if len(req.Rules) > 10000 {
		return HTTPSUpgradeRulesetPlan{}, fmt.Errorf("rule count exceeds 10000")
	}
	p := HTTPSUpgradeRulesetPlan{RuleCount: len(req.Rules), ReadOnly: true, Invariants: []string{"audit never installs browser rules or redirects traffic", "targets are treated as data; donor regex is not executed"}}
	seen := map[string]int{}
	var coverage []string
	for i, r := range req.Rules {
		name := strings.TrimSpace(r.Name)
		if name == "" || len(name) > 160 {
			return HTTPSUpgradeRulesetPlan{}, fmt.Errorf("rule %d has invalid name", i)
		}
		if r.Disabled {
			p.DisabledRules++
		}
		if len(r.Targets) > 256 || len(r.Exclusions) > 256 {
			return HTTPSUpgradeRulesetPlan{}, fmt.Errorf("rule %s exceeds target/exclusion bounds", name)
		}
		for _, t := range r.Targets {
			n := strings.ToLower(strings.TrimSpace(t))
			if !validUpgradeTarget(n) {
				p.InvalidTargets = append(p.InvalidTargets, name+":"+n)
				continue
			}
			seen[n]++
			p.TargetCount++
			coverage = append(coverage, name+"|"+n)
		}
	}
	for t, n := range seen {
		if n > 1 {
			p.DuplicateTargets = append(p.DuplicateTargets, t)
		}
	}
	sort.Strings(p.DuplicateTargets)
	sort.Strings(p.InvalidTargets)
	sort.Strings(coverage)
	h := sha256.Sum256([]byte(strings.Join(coverage, "\n")))
	p.CoverageSHA256 = hex.EncodeToString(h[:])
	return p, nil
}

// Tor exit scan scheduling ----------------------------------------------------

type TorExitScanPlanRequest struct {
	CandidateExits    int      `json:"candidate_exits"`
	RequestedExits    int      `json:"requested_exits"`
	Country           string   `json:"country,omitempty"`
	BuildDelayMS      int      `json:"build_delay_ms"`
	Parallelism       int      `json:"parallelism"`
	PerProbeTimeoutMS int      `json:"per_probe_timeout_ms"`
	Modules           []string `json:"modules"`
}
type TorExitScanPlan struct {
	PlannedExits          int      `json:"planned_exits"`
	Country               string   `json:"country"`
	BuildDelayMS          int      `json:"build_delay_ms"`
	Parallelism           int      `json:"parallelism"`
	PerProbeTimeoutMS     int      `json:"per_probe_timeout_ms"`
	Modules               []string `json:"modules"`
	MinimumScheduleMillis int64    `json:"minimum_schedule_ms"`
	ControlsTor           bool     `json:"controls_tor"`
	BuildsCircuits        bool     `json:"builds_circuits"`
	PerformsNetworkIO     bool     `json:"performs_network_io"`
	ReadOnly              bool     `json:"read_only"`
	Invariants            []string `json:"invariants"`
}

func BuildTorExitScanPlan(r TorExitScanPlanRequest) (TorExitScanPlan, error) {
	if r.CandidateExits < 0 || r.CandidateExits > 100000 {
		return TorExitScanPlan{}, fmt.Errorf("candidate_exits out of range")
	}
	n := r.RequestedExits
	if n == 0 || n > r.CandidateExits {
		n = r.CandidateExits
	}
	if n > 1000 {
		return TorExitScanPlan{}, fmt.Errorf("planned exits exceed 1000")
	}
	c := strings.ToUpper(strings.TrimSpace(r.Country))
	if c != "" && (len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z') {
		return TorExitScanPlan{}, fmt.Errorf("invalid country code")
	}
	d := r.BuildDelayMS
	if d == 0 {
		d = 50
	}
	if d < 50 || d > 60000 {
		return TorExitScanPlan{}, fmt.Errorf("build_delay_ms must be 50..60000")
	}
	par := r.Parallelism
	if par == 0 {
		par = 4
	}
	if par < 1 || par > 32 {
		return TorExitScanPlan{}, fmt.Errorf("parallelism must be 1..32")
	}
	to := r.PerProbeTimeoutMS
	if to == 0 {
		to = 10000
	}
	if to < 100 || to > 120000 {
		return TorExitScanPlan{}, fmt.Errorf("per_probe_timeout_ms out of range")
	}
	allow := map[string]bool{"rtt": true, "dnspoison": true, "cloudflared": true, "checktest": true}
	mods := []string{}
	for _, m := range r.Modules {
		m = strings.ToLower(strings.TrimSpace(m))
		if !allow[m] {
			return TorExitScanPlan{}, fmt.Errorf("unsupported module %q", m)
		}
		mods = append(mods, m)
	}
	if len(mods) == 0 {
		mods = []string{"rtt"}
	}
	sort.Strings(mods)
	waves := int64(math.Ceil(float64(n) / float64(par)))
	return TorExitScanPlan{PlannedExits: n, Country: c, BuildDelayMS: d, Parallelism: par, PerProbeTimeoutMS: to, Modules: mods, MinimumScheduleMillis: waves * int64(d), ReadOnly: true, Invariants: []string{"planner does not control Tor or build circuits", "build delay is at least 50 ms to bound measurement load", "module names are admitted from a closed set"}}, nil
}

// Mobile Tor lifecycle --------------------------------------------------------

type MobileTorLifecyclePlanRequest struct {
	ObservedState    string `json:"observed_state"`
	AppState         string `json:"app_state"`
	RequestedAction  string `json:"requested_action"`
	NetworkAvailable bool   `json:"network_available"`
	OnDemand         bool   `json:"on_demand"`
	BridgeConfigured bool   `json:"bridge_configured"`
}
type MobileTorLifecyclePlan struct {
	ObservedState          string   `json:"observed_state"`
	NextState              string   `json:"next_state"`
	ActionAllowed          bool     `json:"action_allowed"`
	ShouldRemainResident   bool     `json:"should_remain_resident"`
	RequiresNetwork        bool     `json:"requires_network"`
	Warnings               []string `json:"warnings"`
	ControlsTor            bool     `json:"controls_tor"`
	WritesVPNConfiguration bool     `json:"writes_vpn_configuration"`
	PerformsNetworkIO      bool     `json:"performs_network_io"`
	ReadOnly               bool     `json:"read_only"`
	Invariants             []string `json:"invariants"`
}

func BuildMobileTorLifecyclePlan(r MobileTorLifecyclePlanRequest) (MobileTorLifecyclePlan, error) {
	state := strings.ToLower(strings.TrimSpace(r.ObservedState))
	app := strings.ToLower(strings.TrimSpace(r.AppState))
	act := strings.ToLower(strings.TrimSpace(r.RequestedAction))
	if state == "" {
		state = "stopped"
	}
	if app == "" {
		app = "foreground"
	}
	if act == "" {
		act = "none"
	}
	valid := map[string]bool{"stopped": true, "starting": true, "bootstrapping": true, "ready": true, "stopping": true, "failed": true}
	if !valid[state] {
		return MobileTorLifecyclePlan{}, fmt.Errorf("invalid observed_state")
	}
	if app != "foreground" && app != "background" {
		return MobileTorLifecyclePlan{}, fmt.Errorf("invalid app_state")
	}
	if act != "none" && act != "start" && act != "stop" && act != "network-change" {
		return MobileTorLifecyclePlan{}, fmt.Errorf("invalid requested_action")
	}
	p := MobileTorLifecyclePlan{ObservedState: state, NextState: state, ReadOnly: true, RequiresNetwork: state == "starting" || state == "bootstrapping" || state == "ready", Invariants: []string{"UI/app lifecycle state cannot directly grant Tor process authority", "on-demand background residency is explicit", "network loss never converts bootstrapping evidence into ready"}}
	switch act {
	case "start":
		if (state == "stopped" || state == "failed") && r.NetworkAvailable {
			p.ActionAllowed = true
			p.NextState = "starting"
		} else {
			p.Warnings = append(p.Warnings, "start requires stopped/failed state and available network")
		}
	case "stop":
		if state != "stopped" && state != "stopping" {
			p.ActionAllowed = true
			p.NextState = "stopping"
		}
	case "network-change":
		p.ActionAllowed = true
		if !r.NetworkAvailable && (state == "starting" || state == "bootstrapping" || state == "ready") {
			p.NextState = "failed"
			p.Warnings = append(p.Warnings, "network unavailable")
		}
	case "none":
		p.ActionAllowed = true
	}
	p.ShouldRemainResident = r.OnDemand && app == "background" && (p.NextState == "ready" || p.NextState == "bootstrapping" || p.NextState == "starting")
	if !r.BridgeConfigured && p.NextState == "failed" {
		p.Warnings = append(p.Warnings, "bridge configuration may be required in restricted networks")
	}
	return p, nil
}

// Security posture ------------------------------------------------------------

type SecurityPostureCheck struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
}
type SecurityPosturePlanRequest struct {
	Checks []SecurityPostureCheck `json:"checks"`
}
type SecurityPostureGap struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
}
type SecurityPosturePlan struct {
	ApplicableChecks        int                  `json:"applicable_checks"`
	PassedChecks            int                  `json:"passed_checks"`
	FailedChecks            int                  `json:"failed_checks"`
	UnknownChecks           int                  `json:"unknown_checks"`
	WeightedCoveragePercent float64              `json:"weighted_coverage_percent"`
	PriorityGaps            []SecurityPostureGap `json:"priority_gaps"`
	InspectsHost            bool                 `json:"inspects_host"`
	ChangesSettings         bool                 `json:"changes_settings"`
	PerformsNetworkIO       bool                 `json:"performs_network_io"`
	ReadOnly                bool                 `json:"read_only"`
	Invariants              []string             `json:"invariants"`
}

func severityWeight(v string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical":
		return 5, true
	case "high":
		return 3, true
	case "medium":
		return 2, true
	case "low":
		return 1, true
	}
	return 0, false
}
func BuildSecurityPosturePlan(r SecurityPosturePlanRequest) (SecurityPosturePlan, error) {
	if len(r.Checks) == 0 || len(r.Checks) > 256 {
		return SecurityPosturePlan{}, fmt.Errorf("checks must contain 1..256 records")
	}
	p := SecurityPosturePlan{ReadOnly: true, Invariants: []string{"results describe caller-supplied evidence only", "unknown is never treated as pass", "planner does not inspect or change host settings"}}
	seen := map[string]bool{}
	earned, total := 0, 0
	for _, c := range r.Checks {
		id := strings.TrimSpace(c.ID)
		if id == "" || len(id) > 128 || seen[id] {
			return SecurityPosturePlan{}, fmt.Errorf("invalid or duplicate check id")
		}
		seen[id] = true
		w, ok := severityWeight(c.Severity)
		if !ok {
			return SecurityPosturePlan{}, fmt.Errorf("invalid severity for %s", id)
		}
		s := strings.ToLower(strings.TrimSpace(c.Status))
		if s == "not-applicable" {
			continue
		}
		if s != "pass" && s != "fail" && s != "unknown" {
			return SecurityPosturePlan{}, fmt.Errorf("invalid status for %s", id)
		}
		p.ApplicableChecks++
		total += w
		switch s {
		case "pass":
			p.PassedChecks++
			earned += w
		case "fail":
			p.FailedChecks++
			p.PriorityGaps = append(p.PriorityGaps, SecurityPostureGap{ID: id, Category: strings.TrimSpace(c.Category), Severity: strings.ToLower(c.Severity), Status: s})
		case "unknown":
			p.UnknownChecks++
			p.PriorityGaps = append(p.PriorityGaps, SecurityPostureGap{ID: id, Category: strings.TrimSpace(c.Category), Severity: strings.ToLower(c.Severity), Status: s})
		}
	}
	if total > 0 {
		p.WeightedCoveragePercent = math.Round(float64(earned)*10000/float64(total)) / 100
	}
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	sort.SliceStable(p.PriorityGaps, func(i, j int) bool {
		a, b := p.PriorityGaps[i], p.PriorityGaps[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] > rank[b.Severity]
		}
		return a.ID < b.ID
	})
	return p, nil
}

// Traffic shaper / padding policy --------------------------------------------

type TrafficShaperPlanRequest struct {
	RateBytesPerSecond int64   `json:"rate_bytes_per_second"`
	BurstBytes         int64   `json:"burst_bytes"`
	QueueBytes         int64   `json:"queue_bytes"`
	PaddingMinBytes    int     `json:"padding_min_bytes"`
	PaddingMaxBytes    int     `json:"padding_max_bytes"`
	OverheadPercent    float64 `json:"overhead_percent"`
}
type TrafficShaperPlan struct {
	RateBytesPerSecond    int64    `json:"rate_bytes_per_second"`
	BurstBytes            int64    `json:"burst_bytes"`
	QueueBytes            int64    `json:"queue_bytes"`
	PaddingMinBytes       int      `json:"padding_min_bytes"`
	PaddingMaxBytes       int      `json:"padding_max_bytes"`
	BurstDrainMillis      int64    `json:"burst_drain_ms"`
	QueueDrainMillis      int64    `json:"queue_drain_ms"`
	WorstCasePaddingBytes int      `json:"worst_case_padding_bytes"`
	AppliesShaping        bool     `json:"applies_shaping"`
	GeneratesPadding      bool     `json:"generates_padding"`
	PerformsNetworkIO     bool     `json:"performs_network_io"`
	ReadOnly              bool     `json:"read_only"`
	Invariants            []string `json:"invariants"`
}

func BuildTrafficShaperPlan(r TrafficShaperPlanRequest) (TrafficShaperPlan, error) {
	if r.RateBytesPerSecond <= 0 || r.RateBytesPerSecond > 1<<30 {
		return TrafficShaperPlan{}, fmt.Errorf("rate_bytes_per_second out of range")
	}
	if r.BurstBytes < 0 || r.BurstBytes > 32<<20 || r.QueueBytes < 0 || r.QueueBytes > 64<<20 {
		return TrafficShaperPlan{}, fmt.Errorf("burst/queue exceeds bounds")
	}
	if r.PaddingMinBytes < 0 || r.PaddingMaxBytes < r.PaddingMinBytes || r.PaddingMaxBytes > 64<<10 {
		return TrafficShaperPlan{}, fmt.Errorf("padding bounds invalid")
	}
	if r.OverheadPercent < 0 || r.OverheadPercent > 100 {
		return TrafficShaperPlan{}, fmt.Errorf("overhead_percent out of range")
	}
	ceilms := func(b int64) int64 {
		if b == 0 {
			return 0
		}
		return (b*1000 + r.RateBytesPerSecond - 1) / r.RateBytesPerSecond
	}
	return TrafficShaperPlan{RateBytesPerSecond: r.RateBytesPerSecond, BurstBytes: r.BurstBytes, QueueBytes: r.QueueBytes, PaddingMinBytes: r.PaddingMinBytes, PaddingMaxBytes: r.PaddingMaxBytes, BurstDrainMillis: ceilms(r.BurstBytes), QueueDrainMillis: ceilms(r.QueueBytes), WorstCasePaddingBytes: r.PaddingMaxBytes, ReadOnly: true, Invariants: []string{"leaky-bucket sizing is planning evidence only", "padding bounds are explicit and do not generate traffic", "queue capacity is bounded before runtime"}}, nil
}

// Endpoint location evidence --------------------------------------------------

type EndpointLocationObservation struct {
	EndpointID        string  `json:"endpoint_id"`
	AdvertisedCountry string  `json:"advertised_country,omitempty"`
	MeasuredCountry   string  `json:"measured_country,omitempty"`
	Source            string  `json:"source"`
	Confidence        float64 `json:"confidence"`
}
type EndpointLocationDecision struct {
	EndpointID        string  `json:"endpoint_id"`
	Status            string  `json:"status"`
	AdvertisedCountry string  `json:"advertised_country"`
	MeasuredCountry   string  `json:"measured_country"`
	Confidence        float64 `json:"confidence"`
}
type EndpointLocationEvidencePlanRequest struct {
	Observations      []EndpointLocationObservation `json:"observations"`
	MinimumConfidence float64                       `json:"minimum_confidence"`
}
type EndpointLocationEvidencePlan struct {
	Decisions          []EndpointLocationDecision `json:"decisions"`
	Matches            int                        `json:"matches"`
	Mismatches         int                        `json:"mismatches"`
	Unknown            int                        `json:"unknown"`
	SelectionAuthority bool                       `json:"selection_authority"`
	PerformsGeoLookup  bool                       `json:"performs_geo_lookup"`
	PerformsNetworkIO  bool                       `json:"performs_network_io"`
	ReadOnly           bool                       `json:"read_only"`
	Invariants         []string                   `json:"invariants"`
}

func countryEvidence(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if len(v) == 2 && v[0] >= 'A' && v[0] <= 'Z' && v[1] >= 'A' && v[1] <= 'Z' {
		return v
	}
	return ""
}
func BuildEndpointLocationEvidencePlan(r EndpointLocationEvidencePlanRequest) (EndpointLocationEvidencePlan, error) {
	if len(r.Observations) > 1024 {
		return EndpointLocationEvidencePlan{}, fmt.Errorf("observation count exceeds 1024")
	}
	min := r.MinimumConfidence
	if min == 0 {
		min = .7
	}
	if min < 0 || min > 1 {
		return EndpointLocationEvidencePlan{}, fmt.Errorf("minimum_confidence out of range")
	}
	p := EndpointLocationEvidencePlan{ReadOnly: true, Invariants: []string{"geolocation is evidence, never endpoint-selection authority", "low-confidence or missing country evidence remains unknown", "planner performs no GeoIP or network lookup"}}
	seen := map[string]bool{}
	for _, o := range r.Observations {
		id := strings.TrimSpace(o.EndpointID)
		if id == "" || len(id) > 128 || seen[id] {
			return EndpointLocationEvidencePlan{}, fmt.Errorf("invalid or duplicate endpoint_id")
		}
		seen[id] = true
		if o.Confidence < 0 || o.Confidence > 1 {
			return EndpointLocationEvidencePlan{}, fmt.Errorf("confidence out of range for %s", id)
		}
		a, m := countryEvidence(o.AdvertisedCountry), countryEvidence(o.MeasuredCountry)
		status := "unknown"
		if o.Confidence >= min && a != "" && m != "" {
			if a == m {
				status = "match"
				p.Matches++
			} else {
				status = "mismatch"
				p.Mismatches++
			}
		} else {
			p.Unknown++
		}
		p.Decisions = append(p.Decisions, EndpointLocationDecision{EndpointID: id, Status: status, AdvertisedCountry: a, MeasuredCountry: m, Confidence: o.Confidence})
	}
	sort.Slice(p.Decisions, func(i, j int) bool { return p.Decisions[i].EndpointID < p.Decisions[j].EndpointID })
	return p, nil
}
