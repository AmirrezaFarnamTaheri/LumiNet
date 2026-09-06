package dns

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	maxResolverPoolCandidates = 64
	maxResolverFallbacks      = 16
)

type ResolverPoolCandidate struct {
	ID                  string    `json:"id"`
	URL                 string    `json:"url"`
	BootstrapIPs        []string  `json:"bootstrap_ips,omitempty"`
	Priority            int       `json:"priority,omitempty"`
	RTTMs               float64   `json:"rtt_ms,omitempty"`
	CanaryStatus        string    `json:"canary_status,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	CooldownUntil       time.Time `json:"cooldown_until,omitempty"`
}

type ResolverPoolPlanRequest struct {
	Candidates   []ResolverPoolCandidate `json:"candidates"`
	AsOf         time.Time               `json:"as_of,omitempty"`
	MaxFallbacks int                     `json:"max_fallbacks,omitempty"`
}

type ResolverPoolRank struct {
	ID           string   `json:"id"`
	URL          string   `json:"url"`
	BootstrapIPs []string `json:"bootstrap_ips,omitempty"`
	Priority     int      `json:"priority"`
	RTTMs        float64  `json:"rtt_ms,omitempty"`
	CanaryStatus string   `json:"canary_status"`
	CircuitOpen  bool     `json:"circuit_open"`
	Tier         string   `json:"tier"`
	Reason       string   `json:"reason,omitempty"`
}

type ResolverPoolPlan struct {
	Active        []ResolverPoolRank `json:"active"`
	Reserve       []ResolverPoolRank `json:"reserve"`
	Invalid       []ResolverPoolRank `json:"invalid"`
	FallbackOrder []string           `json:"fallback_order"`
	ReadOnly      bool               `json:"read_only"`
}

// ResolverPoolPresets returns credential-free resolver examples. They are
// planning presets only; callers must explicitly choose/configure live DNS.
func ResolverPoolPresets() []ResolverPoolCandidate {
	return []ResolverPoolCandidate{
		{ID: "cloudflare", URL: "https://cloudflare-dns.com/dns-query", BootstrapIPs: []string{"1.1.1.1", "1.0.0.1"}, Priority: 10},
		{ID: "google", URL: "https://dns.google/dns-query", BootstrapIPs: []string{"8.8.8.8", "8.8.4.4"}, Priority: 20},
		{ID: "quad9-standard", URL: "https://dns.quad9.net/dns-query", BootstrapIPs: []string{"9.9.9.9", "149.112.112.112"}, Priority: 30},
		{ID: "quad9-secured", URL: "https://dns9.quad9.net/dns-query", BootstrapIPs: []string{"9.9.9.9", "149.112.112.112"}, Priority: 31},
		{ID: "quad9-unsecured", URL: "https://dns10.quad9.net/dns-query", BootstrapIPs: []string{"9.9.9.10", "149.112.112.10"}, Priority: 32},
		{ID: "quad9-secured-ecs", URL: "https://dns11.quad9.net/dns-query", BootstrapIPs: []string{"9.9.9.11", "149.112.112.11"}, Priority: 33},
	}
}

func containsSensitiveQuery(u *url.URL) bool {
	for key := range u.Query() {
		k := strings.ToLower(key)
		if strings.Contains(k, "token") || strings.Contains(k, "secret") || strings.Contains(k, "password") || strings.Contains(k, "api_key") || strings.Contains(k, "apikey") {
			return true
		}
	}
	return false
}

// BuildResolverPoolPlan is deliberately side-effect free. It validates and
// orders caller-supplied evidence but never contacts or installs a resolver.
func BuildResolverPoolPlan(req ResolverPoolPlanRequest) (ResolverPoolPlan, error) {
	if len(req.Candidates) == 0 || len(req.Candidates) > maxResolverPoolCandidates {
		return ResolverPoolPlan{}, fmt.Errorf("resolver pool size must be between 1 and %d", maxResolverPoolCandidates)
	}
	limit := req.MaxFallbacks
	if limit == 0 {
		limit = 3
	}
	if limit < 1 || limit > maxResolverFallbacks {
		return ResolverPoolPlan{}, fmt.Errorf("max fallbacks must be between 1 and %d", maxResolverFallbacks)
	}
	asOf := req.AsOf
	if asOf.IsZero() {
		asOf = time.Now()
	}
	seen := map[string]struct{}{}
	plan := ResolverPoolPlan{ReadOnly: true, Active: []ResolverPoolRank{}, Reserve: []ResolverPoolRank{}, Invalid: []ResolverPoolRank{}, FallbackOrder: []string{}}
	for _, c := range req.Candidates {
		id := strings.TrimSpace(c.ID)
		if id == "" || len(id) > 128 {
			return ResolverPoolPlan{}, fmt.Errorf("invalid resolver id")
		}
		if _, ok := seen[id]; ok {
			return ResolverPoolPlan{}, fmt.Errorf("duplicate resolver id %q", id)
		}
		seen[id] = struct{}{}
		status := strings.ToLower(strings.TrimSpace(c.CanaryStatus))
		if status == "" {
			status = "unknown"
		}
		if status != "pass" && status != "fail" && status != "unknown" {
			return ResolverPoolPlan{}, fmt.Errorf("invalid canary status for %s", id)
		}
		if c.Priority < 0 || c.Priority > 100000 || c.RTTMs < 0 || c.RTTMs > 120000 || c.ConsecutiveFailures < 0 {
			return ResolverPoolPlan{}, fmt.Errorf("invalid resolver metrics for %s", id)
		}
		rank := ResolverPoolRank{ID: id, URL: c.URL, Priority: c.Priority, RTTMs: c.RTTMs, CanaryStatus: status, BootstrapIPs: append([]string(nil), c.BootstrapIPs...)}
		u, err := url.Parse(strings.TrimSpace(c.URL))
		switch {
		case err != nil || u.Scheme != "https" || u.Hostname() == "":
			rank.Tier, rank.Reason = "invalid", "HTTPS resolver URL required"
		case u.User != nil || containsSensitiveQuery(u):
			rank.Tier, rank.Reason = "invalid", "credential-bearing resolver URL rejected"
		default:
			validBootstrap := true
			for _, raw := range c.BootstrapIPs {
				if net.ParseIP(strings.TrimSpace(raw)) == nil {
					validBootstrap = false
					break
				}
			}
			if !validBootstrap {
				rank.Tier, rank.Reason = "invalid", "invalid bootstrap IP"
				break
			}
			rank.CircuitOpen = c.ConsecutiveFailures >= 3 && (c.CooldownUntil.IsZero() || c.CooldownUntil.After(asOf))
			if status == "pass" && !rank.CircuitOpen {
				rank.Tier = "active"
			} else {
				rank.Tier = "reserve"
				if rank.CircuitOpen {
					rank.Reason = "failure circuit open"
				} else if status == "fail" {
					rank.Reason = "canary failed"
				} else {
					rank.Reason = "canary unknown"
				}
			}
		}
		switch rank.Tier {
		case "active":
			plan.Active = append(plan.Active, rank)
		case "reserve":
			plan.Reserve = append(plan.Reserve, rank)
		default:
			plan.Invalid = append(plan.Invalid, rank)
		}
	}
	less := func(a, b ResolverPoolRank) bool {
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		ar, br := a.RTTMs, b.RTTMs
		if ar == 0 {
			ar = 1e18
		}
		if br == 0 {
			br = 1e18
		}
		if ar != br {
			return ar < br
		}
		return a.ID < b.ID
	}
	sort.SliceStable(plan.Active, func(i, j int) bool { return less(plan.Active[i], plan.Active[j]) })
	sort.SliceStable(plan.Reserve, func(i, j int) bool { return less(plan.Reserve[i], plan.Reserve[j]) })
	sort.SliceStable(plan.Invalid, func(i, j int) bool { return plan.Invalid[i].ID < plan.Invalid[j].ID })
	for _, group := range [][]ResolverPoolRank{plan.Active, plan.Reserve} {
		for _, r := range group {
			if len(plan.FallbackOrder) >= limit {
				break
			}
			plan.FallbackOrder = append(plan.FallbackOrder, r.ID)
		}
	}
	return plan, nil
}
