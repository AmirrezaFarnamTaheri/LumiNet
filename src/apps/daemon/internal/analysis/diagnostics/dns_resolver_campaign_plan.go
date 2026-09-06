package diagnostics

import (
	"crypto/sha256"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const (
	maxDNSCampaignCandidates  = 10_000_000
	maxDNSCampaignConcurrency = 2048
	maxDNSCampaignDrain       = 5000
)

var dnsCampaignLabelRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

type DNSResolverCampaignPlanRequest struct {
	Mode             string `json:"mode"`
	Platform         string `json:"platform"`
	ObservedState    string `json:"observed_state,omitempty"`
	RequestedAction  string `json:"requested_action,omitempty"`
	Domain           string `json:"domain"`
	QueryType        string `json:"query_type,omitempty"`
	CandidateCount   int    `json:"candidate_count"`
	Concurrency      int    `json:"concurrency,omitempty"`
	TimeoutMS        int    `json:"timeout_ms,omitempty"`
	RandomSubdomain  bool   `json:"random_subdomain,omitempty"`
	SelectionSeed    string `json:"selection_seed,omitempty"`
	ResultDrainLimit int    `json:"result_drain_limit,omitempty"`
	QuerySize        int    `json:"query_size,omitempty"`
}

type DNSResolverCampaignPlan struct {
	Mode               string   `json:"mode"`
	Platform           string   `json:"platform"`
	ObservedState      string   `json:"observed_state"`
	RequestedAction    string   `json:"requested_action"`
	NextState          string   `json:"next_state"`
	ActionAllowed      bool     `json:"action_allowed"`
	Domain             string   `json:"domain"`
	QueryType          string   `json:"query_type"`
	CandidateCount     int      `json:"candidate_count"`
	Concurrency        int      `json:"concurrency"`
	BatchSize          int      `json:"batch_size"`
	TimeoutMS          int      `json:"timeout_ms"`
	RandomSubdomain    bool     `json:"random_subdomain"`
	CacheBustLabel     string   `json:"cache_bust_label,omitempty"`
	ResultDrainLimit   int      `json:"result_drain_limit"`
	QuerySize          int      `json:"query_size,omitempty"`
	DownloadsClients   bool     `json:"downloads_clients"`
	MutatesMTU         bool     `json:"mutates_mtu"`
	PerformsNetworkIO  bool     `json:"performs_network_io"`
	StartsWorkerThread bool     `json:"starts_worker_thread"`
	Invariants         []string `json:"invariants"`
	Warnings           []string `json:"warnings,omitempty"`
}

func BuildDNSResolverCampaignPlan(req DNSResolverCampaignPlanRequest) (DNSResolverCampaignPlan, error) {
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "dns"
	}
	if mode != "dns" && mode != "slipstream" && mode != "slipnet" {
		return DNSResolverCampaignPlan{}, fmt.Errorf("mode must be dns, slipstream, or slipnet")
	}
	platform := strings.ToLower(strings.TrimSpace(req.Platform))
	if platform == "" {
		platform = "linux"
	}
	switch platform {
	case "linux", "windows", "macos", "android":
	default:
		return DNSResolverCampaignPlan{}, fmt.Errorf("platform must be linux, windows, macos, or android")
	}
	domain := strings.Trim(strings.TrimSpace(req.Domain), ".")
	if err := validateDNSCampaignName(domain); err != nil {
		return DNSResolverCampaignPlan{}, err
	}
	qtype := strings.ToUpper(strings.TrimSpace(req.QueryType))
	if qtype == "" {
		qtype = "A"
	}
	switch qtype {
	case "A", "AAAA", "MX", "TXT", "NS", "CNAME":
	default:
		return DNSResolverCampaignPlan{}, fmt.Errorf("query_type must be A, AAAA, MX, TXT, NS, or CNAME")
	}
	if req.CandidateCount < 1 || req.CandidateCount > maxDNSCampaignCandidates {
		return DNSResolverCampaignPlan{}, fmt.Errorf("candidate_count must be 1..%d", maxDNSCampaignCandidates)
	}
	concurrency := req.Concurrency
	if concurrency == 0 {
		concurrency = 100
	}
	if concurrency < 1 || concurrency > maxDNSCampaignConcurrency {
		return DNSResolverCampaignPlan{}, fmt.Errorf("concurrency must be 1..%d", maxDNSCampaignConcurrency)
	}
	timeout := req.TimeoutMS
	if timeout == 0 {
		timeout = 2000
	}
	if timeout < 100 || timeout > 30000 {
		return DNSResolverCampaignPlan{}, fmt.Errorf("timeout_ms must be 100..30000")
	}
	drain := req.ResultDrainLimit
	if drain == 0 {
		drain = 500
	}
	if drain < 1 || drain > maxDNSCampaignDrain {
		return DNSResolverCampaignPlan{}, fmt.Errorf("result_drain_limit must be 1..%d", maxDNSCampaignDrain)
	}
	if mode != "slipnet" && req.QuerySize != 0 {
		return DNSResolverCampaignPlan{}, fmt.Errorf("query_size applies only to slipnet mode")
	}
	if mode == "slipnet" && req.QuerySize != 0 && (req.QuerySize < 50 || req.QuerySize > 4096) {
		return DNSResolverCampaignPlan{}, fmt.Errorf("slipnet query_size must be 0 or 50..4096")
	}
	state := strings.ToLower(strings.TrimSpace(req.ObservedState))
	if state == "" {
		state = "idle"
	}
	switch state {
	case "idle", "running", "paused", "stopping", "completed", "error":
	default:
		return DNSResolverCampaignPlan{}, fmt.Errorf("observed_state must be idle, running, paused, stopping, completed, or error")
	}
	action := strings.ToLower(strings.TrimSpace(req.RequestedAction))
	if action == "" {
		action = "inspect"
	}
	next, allowed := dnsCampaignTransition(state, action)

	batch := concurrency / 4
	if batch < 4 {
		batch = 4
	}
	if batch > 16 {
		batch = 16
	}
	plan := DNSResolverCampaignPlan{Mode: mode, Platform: platform, ObservedState: state, RequestedAction: action, NextState: next, ActionAllowed: allowed, Domain: domain, QueryType: qtype, CandidateCount: req.CandidateCount, Concurrency: concurrency, BatchSize: batch, TimeoutMS: timeout, RandomSubdomain: req.RandomSubdomain, ResultDrainLimit: drain, QuerySize: req.QuerySize,
		DownloadsClients: false, MutatesMTU: false, PerformsNetworkIO: false, StartsWorkerThread: false,
		Invariants: []string{
			"candidate, concurrency, timeout, result-drain, and SlipNet query-size bounds are validated before a scan campaign can start",
			"pause/resume/stop are closed lifecycle transitions; resume is accepted only from paused and pause only from running",
			"cache-busting labels are deterministic planning evidence rather than hidden random state",
			"platform-specific socket/event-loop details remain runtime-owner concerns and are not inferred from planner success",
			"Slipstream/SlipNet client download, executable permission changes, OS MTU mutation, and live DNS/proxy probes are outside planner authority",
		},
	}
	if req.RandomSubdomain {
		seed := strings.TrimSpace(req.SelectionSeed)
		if seed == "" {
			seed = fmt.Sprintf("%s|%s|%d", domain, mode, req.CandidateCount)
			plan.Warnings = append(plan.Warnings, "selection_seed omitted; deterministic campaign seed derived from non-secret campaign identity")
		}
		h := sha256.Sum256([]byte(seed))
		plan.CacheBustLabel = fmt.Sprintf("scan-%x", h[:6])
	}
	if !allowed {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("action %q is not valid from state %q", action, state))
	}
	if net.ParseIP(domain) != nil {
		return DNSResolverCampaignPlan{}, fmt.Errorf("domain must be a DNS name, not an IP literal")
	}
	return plan, nil
}

func validateDNSCampaignName(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("domain must be a bounded DNS name")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 || !dnsCampaignLabelRE.MatchString(label) {
			return fmt.Errorf("domain contains invalid DNS label %q", label)
		}
	}
	return nil
}

func dnsCampaignTransition(state, action string) (string, bool) {
	if action == "inspect" {
		return state, true
	}
	switch state {
	case "idle", "completed", "error":
		if action == "start" {
			return "running", true
		}
	case "running":
		if action == "pause" {
			return "paused", true
		}
		if action == "stop" {
			return "stopping", true
		}
	case "paused":
		if action == "resume" {
			return "running", true
		}
		if action == "stop" {
			return "stopping", true
		}
	case "stopping":
		if action == "complete" {
			return "completed", true
		}
	}
	return state, false
}
