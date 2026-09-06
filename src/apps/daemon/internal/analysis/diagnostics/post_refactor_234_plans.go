package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Post-refactor-234 planners are deterministic transforms over caller-supplied
// evidence. They do not fetch feeds, capture traffic, control Tor, install
// filters, mutate system DNS, or write generated specifications.

// DNS blocklist corpus ---------------------------------------------------------
type DNSBlocklistObservation struct {
	Name, Category, Format, SHA256 string
	Entries                        int
}
type DNSBlocklistCorpusRequest struct {
	Lists []DNSBlocklistObservation `json:"lists"`
}
type DNSBlocklistCorpusPlan struct {
	Accepted                                                      int               `json:"accepted"`
	Rejected                                                      map[string]string `json:"rejected"`
	Categories                                                    map[string]int    `json:"categories"`
	TotalEntries                                                  int64             `json:"total_entries"`
	DuplicateDigests                                              []string          `json:"duplicate_digests"`
	CoverageSHA256                                                string            `json:"coverage_sha256"`
	FetchesFeeds, AppliesBlocking, WritesFiles, PerformsNetworkIO bool
	ReadOnly                                                      bool     `json:"read_only"`
	Invariants                                                    []string `json:"invariants"`
}

func BuildDNSBlocklistCorpusPlan(r DNSBlocklistCorpusRequest) (DNSBlocklistCorpusPlan, error) {
	if len(r.Lists) > 2048 {
		return DNSBlocklistCorpusPlan{}, fmt.Errorf("list count exceeds 2048")
	}
	p := DNSBlocklistCorpusPlan{Rejected: map[string]string{}, Categories: map[string]int{}, ReadOnly: true, Invariants: []string{"only caller-supplied list metadata is audited", "list content is never fetched or applied", "duplicate corpus identities remain visible"}}
	seen := map[string]int{}
	cov := []string{}
	validFmt := map[string]bool{"hosts": true, "domains": true, "wildcard": true, "adblock": true, "rpz": true, "ip": true, "json": true, "other": true}
	for i, o := range r.Lists {
		name := strings.TrimSpace(o.Name)
		cat := strings.ToLower(strings.TrimSpace(o.Category))
		f := strings.ToLower(strings.TrimSpace(o.Format))
		h := strings.ToLower(strings.TrimSpace(o.SHA256))
		key := name
		if key == "" {
			key = fmt.Sprintf("index:%d", i)
		}
		if name == "" || len(name) > 160 {
			p.Rejected[key] = "invalid name"
			continue
		}
		if cat == "" || len(cat) > 64 {
			p.Rejected[key] = "invalid category"
			continue
		}
		if !validFmt[f] {
			p.Rejected[key] = "unsupported format"
			continue
		}
		if o.Entries < 0 || o.Entries > 100000000 {
			p.Rejected[key] = "entry count out of range"
			continue
		}
		if len(h) != 64 {
			p.Rejected[key] = "invalid sha256"
			continue
		}
		if _, e := hex.DecodeString(h); e != nil {
			p.Rejected[key] = "invalid sha256"
			continue
		}
		p.Accepted++
		p.Categories[cat]++
		p.TotalEntries += int64(o.Entries)
		seen[h]++
		cov = append(cov, name+"|"+cat+"|"+f+"|"+strconv.Itoa(o.Entries)+"|"+h)
	}
	for h, n := range seen {
		if n > 1 {
			p.DuplicateDigests = append(p.DuplicateDigests, h)
		}
	}
	sort.Strings(p.DuplicateDigests)
	sort.Strings(cov)
	sum := sha256.Sum256([]byte(strings.Join(cov, "\n")))
	p.CoverageSHA256 = hex.EncodeToString(sum[:])
	return p, nil
}

// Passive API trace schema inference -----------------------------------------
type APITraceObservation struct {
	Method, Path, ContentType string
	Status                    int
	QueryKeys                 []string `json:"query_keys"`
	HeaderKeys                []string `json:"header_keys"`
	BodyFields                []string `json:"body_fields"`
}
type APITraceSchemaRequest struct {
	Observations []APITraceObservation `json:"observations"`
}
type APITraceEndpoint struct {
	Method, PathTemplate   string
	Samples                int
	Statuses               []int    `json:"statuses"`
	ContentTypes           []string `json:"content_types"`
	QueryKeys              []string `json:"query_keys"`
	HeaderKeys             []string `json:"header_keys"`
	BodyFields             []string `json:"body_fields"`
	SensitiveFieldsOmitted int      `json:"sensitive_fields_omitted"`
}
type APITraceSchemaPlan struct {
	Endpoints                                                         []APITraceEndpoint `json:"endpoints"`
	Rejected                                                          map[string]string  `json:"rejected"`
	SchemaSHA256                                                      string             `json:"schema_sha256"`
	CapturesTraffic, RunsMITM, WritesSpecification, PerformsNetworkIO bool
	ReadOnly                                                          bool     `json:"read_only"`
	Invariants                                                        []string `json:"invariants"`
}

var uuidSeg = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var intSeg = regexp.MustCompile(`^[0-9]{1,20}$`)

func apiTemplate(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 || !strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\r\n") {
		return "", false
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	parts := strings.Split(raw, "/")
	for i := 1; i < len(parts); i++ {
		if intSeg.MatchString(parts[i]) || uuidSeg.MatchString(parts[i]) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/"), true
}
func BuildAPITraceSchemaPlan(r APITraceSchemaRequest) (APITraceSchemaPlan, error) {
	if len(r.Observations) > 10000 {
		return APITraceSchemaPlan{}, fmt.Errorf("observation count exceeds 10000")
	}
	p := APITraceSchemaPlan{Rejected: map[string]string{}, ReadOnly: true, Invariants: []string{"schema inference consumes already-captured metadata only", "query values are excluded from path templates", "sensitive authorization/cookie header names are omitted from inferred schema fields", "request-field aggregation is set-like and deterministic across samples", "no interception certificate or proxy authority is created"}}
	type agg struct {
		n       int
		st      map[int]bool
		ct      map[string]bool
		q       map[string]bool
		h       map[string]bool
		b       map[string]bool
		omitted int
	}
	m := map[string]*agg{}
	methods := map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true}
	for i, o := range r.Observations {
		method := strings.ToUpper(strings.TrimSpace(o.Method))
		path, ok := apiTemplate(o.Path)
		if !methods[method] || !ok || o.Status < 100 || o.Status > 599 {
			p.Rejected[fmt.Sprintf("index:%d", i)] = "invalid method/path/status"
			continue
		}
		k := method + " " + path
		if m[k] == nil {
			m[k] = &agg{st: map[int]bool{}, ct: map[string]bool{}, q: map[string]bool{}, h: map[string]bool{}, b: map[string]bool{}}
		}
		a := m[k]
		a.n++
		a.st[o.Status] = true
		ct := strings.ToLower(strings.TrimSpace(strings.Split(o.ContentType, ";")[0]))
		if ct != "" && len(ct) <= 128 {
			a.ct[ct] = true
		}
		q, _ := normalizeSchemaKeys(o.QueryKeys, false)
		for _, key := range q {
			a.q[key] = true
		}
		h, omitted := normalizeSchemaKeys(o.HeaderKeys, true)
		a.omitted += omitted
		for _, key := range h {
			a.h[key] = true
		}
		b, _ := normalizeSchemaKeys(o.BodyFields, false)
		for _, key := range b {
			a.b[key] = true
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cov := []string{}
	for _, k := range keys {
		a := m[k]
		sp := strings.IndexByte(k, ' ')
		e := APITraceEndpoint{Method: k[:sp], PathTemplate: k[sp+1:], Samples: a.n}
		for s := range a.st {
			e.Statuses = append(e.Statuses, s)
		}
		sort.Ints(e.Statuses)
		for c := range a.ct {
			e.ContentTypes = append(e.ContentTypes, c)
		}
		for q := range a.q {
			e.QueryKeys = append(e.QueryKeys, q)
		}
		for h := range a.h {
			e.HeaderKeys = append(e.HeaderKeys, h)
		}
		for b := range a.b {
			e.BodyFields = append(e.BodyFields, b)
		}
		sort.Strings(e.ContentTypes)
		sort.Strings(e.QueryKeys)
		sort.Strings(e.HeaderKeys)
		sort.Strings(e.BodyFields)
		e.SensitiveFieldsOmitted = a.omitted
		p.Endpoints = append(p.Endpoints, e)
		cov = append(cov, fmt.Sprintf("%s|%d|%v|%v|%v|%v|%v|%d", k, a.n, e.Statuses, e.ContentTypes, e.QueryKeys, e.HeaderKeys, e.BodyFields, e.SensitiveFieldsOmitted))
	}
	sum := sha256.Sum256([]byte(strings.Join(cov, "\n")))
	p.SchemaSHA256 = hex.EncodeToString(sum[:])
	return p, nil
}

// Tor descriptor evidence -----------------------------------------------------
type TorRelayObservation struct {
	Fingerprint, Country    string
	Flags                   []string
	AdvertisedBandwidthKBPS int
}
type TorDescriptorEvidenceRequest struct {
	Relays []TorRelayObservation `json:"relays"`
}
type TorDescriptorEvidencePlan struct {
	Accepted, Rejected, Running, Valid, Exit, Guard                  int
	Countries                                                        map[string]int `json:"countries"`
	CoverageSHA256                                                   string         `json:"coverage_sha256"`
	SelectsRelay, FetchesDescriptors, ControlsTor, PerformsNetworkIO bool
	ReadOnly                                                         bool     `json:"read_only"`
	Invariants                                                       []string `json:"invariants"`
}

func BuildTorDescriptorEvidencePlan(r TorDescriptorEvidenceRequest) (TorDescriptorEvidencePlan, error) {
	if len(r.Relays) > 20000 {
		return TorDescriptorEvidencePlan{}, fmt.Errorf("relay count exceeds 20000")
	}
	p := TorDescriptorEvidencePlan{Countries: map[string]int{}, ReadOnly: true, Invariants: []string{"relay flags are descriptive evidence, not trust or routing authority", "fingerprints must be canonical 40-hex identities", "descriptor fetching and Tor control remain separate owners"}}
	cov := []string{}
	allow := map[string]bool{"running": true, "valid": true, "exit": true, "guard": true, "fast": true, "stable": true, "hsdir": true, "badexit": true, "authority": true, "v2dir": true}
	for _, o := range r.Relays {
		fp := strings.ToUpper(strings.TrimSpace(o.Fingerprint))
		if len(fp) != 40 {
			p.Rejected++
			continue
		}
		if _, e := hex.DecodeString(fp); e != nil {
			p.Rejected++
			continue
		}
		if o.AdvertisedBandwidthKBPS < 0 || o.AdvertisedBandwidthKBPS > 100000000 {
			p.Rejected++
			continue
		}
		cc := strings.ToUpper(strings.TrimSpace(o.Country))
		if cc != "" && (len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z') {
			p.Rejected++
			continue
		}
		fs := []string{}
		ok := true
		seen := map[string]bool{}
		for _, f := range o.Flags {
			f = strings.ToLower(strings.TrimSpace(f))
			if !allow[f] {
				ok = false
				break
			}
			if !seen[f] {
				seen[f] = true
				fs = append(fs, f)
			}
		}
		if !ok {
			p.Rejected++
			continue
		}
		sort.Strings(fs)
		p.Accepted++
		if cc != "" {
			p.Countries[cc]++
		}
		if seen["running"] {
			p.Running++
		}
		if seen["valid"] {
			p.Valid++
		}
		if seen["exit"] {
			p.Exit++
		}
		if seen["guard"] {
			p.Guard++
		}
		cov = append(cov, fp+"|"+cc+"|"+strings.Join(fs, ",")+"|"+strconv.Itoa(o.AdvertisedBandwidthKBPS))
	}
	sort.Strings(cov)
	s := sha256.Sum256([]byte(strings.Join(cov, "\n")))
	p.CoverageSHA256 = hex.EncodeToString(s[:])
	return p, nil
}

// Process-aware proxy rules ---------------------------------------------------
type ProcessProxyRuleObservation struct {
	Process, Protocol, Target, Action string
	PortStart, PortEnd, Priority      int
}
type ProcessProxyRuleRequest struct {
	ProxyProcess string                        `json:"proxy_process"`
	Rules        []ProcessProxyRuleObservation `json:"rules"`
}
type ProcessProxyRuleFinding struct {
	Earlier int    `json:"earlier"`
	Later   int    `json:"later"`
	Kind    string `json:"kind"`
}
type ProcessProxyRulePlan struct {
	Accepted                                                      []ProcessProxyRuleObservation `json:"accepted"`
	Rejected                                                      map[string]string             `json:"rejected"`
	ProxyLoopRisks                                                []int                         `json:"proxy_loop_risks"`
	Findings                                                      []ProcessProxyRuleFinding     `json:"findings"`
	InstallsDriver, AppliesRules, OpensSockets, PerformsNetworkIO bool
	ReadOnly                                                      bool     `json:"read_only"`
	Invariants                                                    []string `json:"invariants"`
}

func validTarget(v string) bool {
	v = strings.TrimSpace(v)
	if v == "*" {
		return true
	}
	if net.ParseIP(v) != nil {
		return true
	}
	if _, _, e := net.ParseCIDR(v); e == nil {
		return true
	}
	if len(v) == 0 || len(v) > 253 || strings.ContainsAny(v, " /:@?#") {
		return false
	}
	return true
}
func BuildProcessProxyRulePlan(r ProcessProxyRuleRequest) (ProcessProxyRulePlan, error) {
	if len(r.Rules) > 4096 {
		return ProcessProxyRulePlan{}, fmt.Errorf("rule count exceeds 4096")
	}
	p := ProcessProxyRulePlan{Rejected: map[string]string{}, ReadOnly: true, Invariants: []string{"rule compilation is metadata-only", "proxy process matches are reported as loop risks", "ordered conflicts and shadowing remain explicit instead of depending on hidden last-wins behavior", "kernel/network-extension installation remains outside this planner"}}
	proxy := strings.ToLower(strings.TrimSpace(r.ProxyProcess))
	type indexedRule struct {
		idx  int
		rule ProcessProxyRuleObservation
	}
	accepted := []indexedRule{}
	for i, o := range r.Rules {
		proc := strings.TrimSpace(o.Process)
		proto := strings.ToLower(strings.TrimSpace(o.Protocol))
		action := strings.ToLower(strings.TrimSpace(o.Action))
		if proc == "" || len(proc) > 260 || !(proto == "tcp" || proto == "udp" || proto == "both") || !(action == "direct" || action == "proxy" || action == "block") || !validTarget(o.Target) || o.PortStart < 0 || o.PortStart > 65535 || o.PortEnd < 0 || o.PortEnd > 65535 || (o.PortEnd != 0 && o.PortEnd < o.PortStart) || o.Priority < 0 || o.Priority > 100000 {
			p.Rejected[fmt.Sprintf("index:%d", i)] = "invalid rule"
			continue
		}
		o.Process, o.Protocol, o.Action, o.Target = proc, proto, action, strings.TrimSpace(o.Target)
		accepted = append(accepted, indexedRule{idx: i, rule: o})
		if proxy != "" && strings.EqualFold(proc, proxy) && action == "proxy" {
			p.ProxyLoopRisks = append(p.ProxyLoopRisks, i)
		}
	}
	sort.SliceStable(accepted, func(i, j int) bool {
		if accepted[i].rule.Priority == accepted[j].rule.Priority {
			return accepted[i].idx < accepted[j].idx
		}
		return accepted[i].rule.Priority < accepted[j].rule.Priority
	})
	for _, ir := range accepted {
		p.Accepted = append(p.Accepted, ir.rule)
	}
	portEnd := func(r ProcessProxyRuleObservation) int {
		if r.PortEnd == 0 {
			return r.PortStart
		}
		return r.PortEnd
	}
	protoOverlap := func(a, b string) bool { return a == "both" || b == "both" || a == b }
	for i := 0; i < len(accepted); i++ {
		a := accepted[i]
		for j := i + 1; j < len(accepted); j++ {
			b := accepted[j]
			if !strings.EqualFold(a.rule.Process, b.rule.Process) || !protoOverlap(a.rule.Protocol, b.rule.Protocol) {
				continue
			}
			if portEnd(a.rule) < b.rule.PortStart || portEnd(b.rule) < a.rule.PortStart {
				continue
			}
			targetOverlap := a.rule.Target == "*" || b.rule.Target == "*" || strings.EqualFold(a.rule.Target, b.rule.Target)
			if !targetOverlap {
				continue
			}
			kind := "overlap"
			if a.rule.Action != b.rule.Action {
				kind = "conflict"
			}
			if a.rule.Target == "*" && a.rule.PortStart <= b.rule.PortStart && portEnd(a.rule) >= portEnd(b.rule) {
				kind = "shadowed"
			}
			p.Findings = append(p.Findings, ProcessProxyRuleFinding{Earlier: a.idx, Later: b.idx, Kind: kind})
		}
	}
	return p, nil
}

// Cryptographic evidence-chain assessment -----------------------------------
type EvidenceArtifactObservation struct{ ID, SHA256, SignatureStatus, TimestampStatus string }
type EvidenceChainRequest struct {
	Artifacts []EvidenceArtifactObservation `json:"artifacts"`
}
type EvidenceChainPlan struct {
	Passed, Failed, Unknown                                           int
	PriorityGaps                                                      []string `json:"priority_gaps"`
	CoverageSHA256                                                    string   `json:"coverage_sha256"`
	SignsArtifacts, VerifiesExternally, ReadsFiles, PerformsNetworkIO bool
	ReadOnly                                                          bool     `json:"read_only"`
	Invariants                                                        []string `json:"invariants"`
}

func BuildEvidenceChainPlan(r EvidenceChainRequest) (EvidenceChainPlan, error) {
	if len(r.Artifacts) > 4096 {
		return EvidenceChainPlan{}, fmt.Errorf("artifact count exceeds 4096")
	}
	p := EvidenceChainPlan{ReadOnly: true, Invariants: []string{"unknown signature or timestamp state never counts as pass", "artifact bytes are not read by this planner", "caller-supplied digest metadata is preserved deterministically"}}
	cov := []string{}
	for i, o := range r.Artifacts {
		id := strings.TrimSpace(o.ID)
		h := strings.ToLower(strings.TrimSpace(o.SHA256))
		sig := strings.ToLower(strings.TrimSpace(o.SignatureStatus))
		ts := strings.ToLower(strings.TrimSpace(o.TimestampStatus))
		if id == "" || len(id) > 128 || len(h) != 64 {
			return EvidenceChainPlan{}, fmt.Errorf("artifact %d invalid identity", i)
		}
		if _, e := hex.DecodeString(h); e != nil {
			return EvidenceChainPlan{}, fmt.Errorf("artifact %d invalid sha256", i)
		}
		if !(sig == "pass" || sig == "fail" || sig == "unknown" || sig == "not-applicable") || !(ts == "pass" || ts == "fail" || ts == "unknown" || ts == "not-applicable") {
			return EvidenceChainPlan{}, fmt.Errorf("artifact %d invalid state", i)
		}
		switch {
		case sig == "fail" || ts == "fail":
			p.Failed++
			p.PriorityGaps = append(p.PriorityGaps, id+":failed-evidence")
		case sig == "unknown" || ts == "unknown":
			p.Unknown++
			p.PriorityGaps = append(p.PriorityGaps, id+":unknown-evidence")
		default:
			p.Passed++
		}
		cov = append(cov, id+"|"+h+"|"+sig+"|"+ts)
	}
	sort.Strings(p.PriorityGaps)
	sort.Strings(cov)
	s := sha256.Sum256([]byte(strings.Join(cov, "\n")))
	p.CoverageSHA256 = hex.EncodeToString(s[:])
	return p, nil
}

// DNSCrypt resolver policy ----------------------------------------------------
type DNSCryptResolverObservation struct {
	Name, Protocol                         string
	DNSSEC, NoLog, NoFilter, SupportsRelay bool
	LatencyMS                              int
}
type DNSCryptResolverPolicyRequest struct {
	RequireDNSSEC, RequireNoLog, RequireNoFilter bool
	MaxLatencyMS                                 int
	Resolvers                                    []DNSCryptResolverObservation `json:"resolvers"`
}
type DNSCryptResolverDecision struct {
	Name, Protocol   string
	LatencyMS, Score int
	SupportsRelay    bool
}
type DNSCryptResolverPolicyPlan struct {
	Eligible                                                              []DNSCryptResolverDecision `json:"eligible"`
	Rejected                                                              map[string]string          `json:"rejected"`
	FetchesResolverList, ChangesSystemDNS, StartsProxy, PerformsNetworkIO bool
	ReadOnly                                                              bool     `json:"read_only"`
	Invariants                                                            []string `json:"invariants"`
}

func BuildDNSCryptResolverPolicyPlan(r DNSCryptResolverPolicyRequest) (DNSCryptResolverPolicyPlan, error) {
	if len(r.Resolvers) > 4096 {
		return DNSCryptResolverPolicyPlan{}, fmt.Errorf("resolver count exceeds 4096")
	}
	max := r.MaxLatencyMS
	if max == 0 {
		max = 3000
	}
	if max < 1 || max > 60000 {
		return DNSCryptResolverPolicyPlan{}, fmt.Errorf("max_latency_ms out of range")
	}
	p := DNSCryptResolverPolicyPlan{Rejected: map[string]string{}, ReadOnly: true, Invariants: []string{"resolver ranking uses caller-supplied observations only", "policy never downloads resolver lists or changes system DNS", "privacy capability claims remain explicit inputs rather than inferred facts"}}
	for i, o := range r.Resolvers {
		name := strings.TrimSpace(o.Name)
		proto := strings.ToLower(strings.TrimSpace(o.Protocol))
		key := name
		if key == "" {
			key = fmt.Sprintf("index:%d", i)
		}
		if name == "" || len(name) > 128 || !(proto == "dnscrypt" || proto == "doh" || proto == "dot" || proto == "odoh") || o.LatencyMS < 0 || o.LatencyMS > 60000 {
			p.Rejected[key] = "invalid resolver"
			continue
		}
		if r.RequireDNSSEC && !o.DNSSEC {
			p.Rejected[key] = "dnssec required"
			continue
		}
		if r.RequireNoLog && !o.NoLog {
			p.Rejected[key] = "no-log required"
			continue
		}
		if r.RequireNoFilter && !o.NoFilter {
			p.Rejected[key] = "no-filter required"
			continue
		}
		if o.LatencyMS > max {
			p.Rejected[key] = "latency exceeds maximum"
			continue
		}
		score := 100000 - o.LatencyMS
		if o.DNSSEC {
			score += 2000
		}
		if o.NoLog {
			score += 2000
		}
		if o.NoFilter {
			score += 1000
		}
		if o.SupportsRelay {
			score += 500
		}
		p.Eligible = append(p.Eligible, DNSCryptResolverDecision{Name: name, Protocol: proto, LatencyMS: o.LatencyMS, Score: score, SupportsRelay: o.SupportsRelay})
	}
	sort.SliceStable(p.Eligible, func(i, j int) bool {
		if p.Eligible[i].Score == p.Eligible[j].Score {
			return p.Eligible[i].Name < p.Eligible[j].Name
		}
		return p.Eligible[i].Score > p.Eligible[j].Score
	})
	return p, nil
}
