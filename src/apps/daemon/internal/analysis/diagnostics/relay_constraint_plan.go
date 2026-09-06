package diagnostics

import (
	"fmt"
	"sort"
	"strings"
)

const (
	maxRelayConstraintCandidates = 512
	maxRelayConstraintValues     = 64
)

type RelayConstraintCandidate struct {
	ID          string   `json:"id"`
	Country     string   `json:"country,omitempty"`
	City        string   `json:"city,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	Provider    string   `json:"provider,omitempty"`
	Owned       bool     `json:"owned,omitempty"`
	Active      bool     `json:"active"`
	IPVersions  []string `json:"ip_versions,omitempty"`
	Ports       []int    `json:"ports,omitempty"`
	Features    []string `json:"features,omitempty"`
	Obfuscation []string `json:"obfuscation,omitempty"`
}

type RelayConstraints struct {
	Country          string   `json:"country,omitempty"`
	City             string   `json:"city,omitempty"`
	Hostname         string   `json:"hostname,omitempty"`
	Providers        []string `json:"providers,omitempty"`
	Ownership        string   `json:"ownership,omitempty"`
	IPVersion        string   `json:"ip_version,omitempty"`
	Port             int      `json:"port,omitempty"`
	RequiredFeatures []string `json:"required_features,omitempty"`
	Obfuscation      string   `json:"obfuscation,omitempty"`
}

type RelayConstraintPlanRequest struct {
	Mode       string                     `json:"mode"`
	Candidates []RelayConstraintCandidate `json:"candidates"`
	Entry      RelayConstraints           `json:"entry,omitempty"`
	Exit       RelayConstraints           `json:"exit,omitempty"`
}

type RelayRejection struct {
	ID      string   `json:"id"`
	Reasons []string `json:"reasons"`
}

type RelayConstraintPlan struct {
	Mode                    string           `json:"mode"`
	EligibleSinglehop       []string         `json:"eligible_singlehop"`
	EligibleEntry           []string         `json:"eligible_entry"`
	EligibleExit            []string         `json:"eligible_exit"`
	RejectedEntry           []RelayRejection `json:"rejected_entry"`
	RejectedExit            []RelayRejection `json:"rejected_exit"`
	SuggestedEntry          string           `json:"suggested_entry,omitempty"`
	SuggestedExit           string           `json:"suggested_exit,omitempty"`
	AutohopUsesMultihop     bool             `json:"autohop_uses_multihop"`
	RequiresEndpointScoring bool             `json:"requires_endpoint_scoring"`
	PerformsNetworkIO       bool             `json:"performs_network_io"`
	InstallsTunnel          bool             `json:"installs_tunnel"`
	Invariants              []string         `json:"invariants"`
	ReadOnly                bool             `json:"read_only"`
}

func BuildRelayConstraintPlan(req RelayConstraintPlanRequest) (RelayConstraintPlan, error) {
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "singlehop"
	}
	switch mode {
	case "singlehop", "multihop", "autohop":
	default:
		return RelayConstraintPlan{}, fmt.Errorf("mode must be singlehop, multihop, or autohop")
	}
	if len(req.Candidates) == 0 || len(req.Candidates) > maxRelayConstraintCandidates {
		return RelayConstraintPlan{}, fmt.Errorf("relay candidate count must be between 1 and %d", maxRelayConstraintCandidates)
	}
	entry, err := normalizeRelayConstraints(req.Entry)
	if err != nil {
		return RelayConstraintPlan{}, fmt.Errorf("entry constraints: %w", err)
	}
	exit, err := normalizeRelayConstraints(req.Exit)
	if err != nil {
		return RelayConstraintPlan{}, fmt.Errorf("exit constraints: %w", err)
	}

	plan := RelayConstraintPlan{
		Mode: mode, RequiresEndpointScoring: true, PerformsNetworkIO: false, InstallsTunnel: false, ReadOnly: true,
		Invariants: []string{
			"relay eligibility is separated from endpoint health/quality scoring",
			"inactive relays never gain selection eligibility",
			"provider, ownership, location, IP-family, port, feature, and obfuscation requirements are conjunctive",
			"multihop entry and exit identities must differ",
			"explicit obfuscation modes are admitted only when the selected entry advertises that capability",
			"autohop prefers a valid singlehop path and falls back to multihop eligibility only when singlehop cannot satisfy the full constraints",
			"the planner performs no remote probe and starts no tunnel; eligible relays must still pass the existing endpoint-pool scorer",
		},
	}
	ids := map[string]bool{}
	for i, raw := range req.Candidates {
		c, err := normalizeRelayCandidate(raw)
		if err != nil {
			return RelayConstraintPlan{}, fmt.Errorf("relay candidate %d: %w", i, err)
		}
		if ids[c.ID] {
			return RelayConstraintPlan{}, fmt.Errorf("duplicate relay id %q", c.ID)
		}
		ids[c.ID] = true

		entryReasons := relayConstraintReasons(c, entry)
		exitReasons := relayConstraintReasons(c, exit)
		if len(entryReasons) == 0 {
			plan.EligibleEntry = append(plan.EligibleEntry, c.ID)
		} else {
			plan.RejectedEntry = append(plan.RejectedEntry, RelayRejection{ID: c.ID, Reasons: entryReasons})
		}
		if len(exitReasons) == 0 {
			plan.EligibleExit = append(plan.EligibleExit, c.ID)
		} else {
			plan.RejectedExit = append(plan.RejectedExit, RelayRejection{ID: c.ID, Reasons: exitReasons})
		}
		if len(entryReasons) == 0 && len(exitReasons) == 0 {
			plan.EligibleSinglehop = append(plan.EligibleSinglehop, c.ID)
		}
	}
	sort.Strings(plan.EligibleEntry)
	sort.Strings(plan.EligibleExit)
	sort.Strings(plan.EligibleSinglehop)
	sort.Slice(plan.RejectedEntry, func(i, j int) bool { return plan.RejectedEntry[i].ID < plan.RejectedEntry[j].ID })
	sort.Slice(plan.RejectedExit, func(i, j int) bool { return plan.RejectedExit[i].ID < plan.RejectedExit[j].ID })

	if mode == "singlehop" {
		if len(plan.EligibleSinglehop) > 0 {
			plan.SuggestedExit = plan.EligibleSinglehop[0]
		}
		return plan, nil
	}
	if mode == "autohop" && len(plan.EligibleSinglehop) > 0 {
		plan.SuggestedExit = plan.EligibleSinglehop[0]
		return plan, nil
	}
	if mode == "autohop" {
		plan.AutohopUsesMultihop = true
	}
	for _, exitID := range plan.EligibleExit {
		for _, entryID := range plan.EligibleEntry {
			if entryID == exitID {
				continue
			}
			plan.SuggestedEntry, plan.SuggestedExit = entryID, exitID
			return plan, nil
		}
	}
	return plan, nil
}

func normalizeRelayConstraints(c RelayConstraints) (RelayConstraints, error) {
	c.Country = strings.ToLower(strings.TrimSpace(c.Country))
	c.City = strings.ToLower(strings.TrimSpace(c.City))
	c.Hostname = strings.ToLower(strings.TrimSpace(c.Hostname))
	c.Ownership = strings.ToLower(strings.TrimSpace(c.Ownership))
	c.IPVersion = strings.ToLower(strings.TrimSpace(c.IPVersion))
	c.Obfuscation = strings.ToLower(strings.TrimSpace(c.Obfuscation))
	if c.Ownership == "" {
		c.Ownership = "any"
	}
	if c.IPVersion == "" {
		c.IPVersion = "any"
	}
	if c.Obfuscation == "" {
		c.Obfuscation = "auto"
	}
	switch c.Ownership {
	case "any", "owned", "rented":
	default:
		return c, fmt.Errorf("ownership must be any, owned, or rented")
	}
	switch c.IPVersion {
	case "any", "4", "6":
	default:
		return c, fmt.Errorf("ip_version must be any, 4, or 6")
	}
	switch c.Obfuscation {
	case "auto", "off", "udp2tcp", "shadowsocks", "quic", "lwo":
	default:
		return c, fmt.Errorf("unsupported obfuscation mode %q", c.Obfuscation)
	}
	if c.Port < 0 || c.Port > 65535 {
		return c, fmt.Errorf("port must be 0..65535")
	}
	if len(c.Providers) > maxRelayConstraintValues || len(c.RequiredFeatures) > maxRelayConstraintValues {
		return c, fmt.Errorf("constraint value count exceeds %d", maxRelayConstraintValues)
	}
	c.Providers = normalizeStringSet(c.Providers)
	c.RequiredFeatures = normalizeStringSet(c.RequiredFeatures)
	return c, nil
}

func normalizeRelayCandidate(c RelayConstraintCandidate) (RelayConstraintCandidate, error) {
	c.ID = strings.TrimSpace(c.ID)
	if c.ID == "" || len(c.ID) > 128 {
		return c, fmt.Errorf("id must be 1..128 bytes")
	}
	c.Country = strings.ToLower(strings.TrimSpace(c.Country))
	c.City = strings.ToLower(strings.TrimSpace(c.City))
	c.Hostname = strings.ToLower(strings.TrimSpace(c.Hostname))
	c.Provider = strings.ToLower(strings.TrimSpace(c.Provider))
	c.IPVersions = normalizeStringSet(c.IPVersions)
	c.Features = normalizeStringSet(c.Features)
	c.Obfuscation = normalizeStringSet(c.Obfuscation)
	if len(c.IPVersions) > 2 || len(c.Features) > maxRelayConstraintValues || len(c.Obfuscation) > maxRelayConstraintValues || len(c.Ports) > maxRelayConstraintValues {
		return c, fmt.Errorf("candidate capability count exceeds bounds")
	}
	for _, v := range c.IPVersions {
		if v != "4" && v != "6" {
			return c, fmt.Errorf("unsupported IP version %q", v)
		}
	}
	seenPort := map[int]bool{}
	ports := make([]int, 0, len(c.Ports))
	for _, p := range c.Ports {
		if p < 1 || p > 65535 {
			return c, fmt.Errorf("port %d outside 1..65535", p)
		}
		if !seenPort[p] {
			seenPort[p] = true
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	c.Ports = ports
	return c, nil
}

func normalizeStringSet(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
func containsString(values []string, want string) bool {
	i := sort.SearchStrings(values, want)
	return i < len(values) && values[i] == want
}
func containsInt(values []int, want int) bool {
	i := sort.SearchInts(values, want)
	return i < len(values) && values[i] == want
}

func relayConstraintReasons(c RelayConstraintCandidate, q RelayConstraints) []string {
	var reasons []string
	if !c.Active {
		reasons = append(reasons, "inactive")
	}
	if q.Country != "" && c.Country != q.Country {
		reasons = append(reasons, "country")
	}
	if q.City != "" && c.City != q.City {
		reasons = append(reasons, "city")
	}
	if q.Hostname != "" && c.Hostname != q.Hostname {
		reasons = append(reasons, "hostname")
	}
	if len(q.Providers) > 0 && !containsString(q.Providers, c.Provider) {
		reasons = append(reasons, "provider")
	}
	if q.Ownership == "owned" && !c.Owned {
		reasons = append(reasons, "ownership")
	}
	if q.Ownership == "rented" && c.Owned {
		reasons = append(reasons, "ownership")
	}
	if q.IPVersion != "any" && !containsString(c.IPVersions, q.IPVersion) {
		reasons = append(reasons, "ip-version")
	}
	if q.Port != 0 && !containsInt(c.Ports, q.Port) {
		reasons = append(reasons, "port")
	}
	for _, f := range q.RequiredFeatures {
		if !containsString(c.Features, f) {
			reasons = append(reasons, "feature:"+f)
		}
	}
	if q.Obfuscation != "auto" && q.Obfuscation != "off" && !containsString(c.Obfuscation, q.Obfuscation) {
		reasons = append(reasons, "obfuscation:"+q.Obfuscation)
	}
	return reasons
}
