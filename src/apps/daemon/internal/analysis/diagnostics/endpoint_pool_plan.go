package diagnostics

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"time"
)

const endpointDiversityBand = 5.0

type EndpointPoolObservation struct {
	Endpoint            string    `json:"endpoint"`
	Successes           int       `json:"successes"`
	Failures            int       `json:"failures"`
	LatencyMs           float64   `json:"latency_ms,omitempty"`
	JitterMs            float64   `json:"jitter_ms,omitempty"`
	PacketLossPct       float64   `json:"packet_loss_pct,omitempty"`
	RemainingQuota      int64     `json:"remaining_quota,omitempty"`
	QuotaLimit          int64     `json:"quota_limit,omitempty"`
	QuotaSafetyBuffer   int64     `json:"quota_safety_buffer,omitempty"`
	QuotaResetAt        time.Time `json:"quota_reset_at,omitempty"`
	LastSucceeded       time.Time `json:"last_succeeded,omitempty"`
	LastFailed          time.Time `json:"last_failed,omitempty"`
	Disabled            bool      `json:"disabled,omitempty"`
	HealthState         string    `json:"health_state,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	CooldownUntil       time.Time `json:"cooldown_until,omitempty"`
	Capacity            int       `json:"capacity,omitempty"`
	InFlight            int       `json:"in_flight,omitempty"`
	Weight              float64   `json:"weight,omitempty"`
}

// EndpointPoolOptions changes dispatch preference without changing eligibility.
// Scope is used only to diversify near-equivalent endpoints deterministically;
// it must not contain secrets. PreviousSuccessful is a remembered last-known-
// good endpoint hint and is honored only when that endpoint is still eligible.
type EndpointPoolOptions struct {
	Scope              string    `json:"scope,omitempty"`
	PreviousSuccessful string    `json:"previous_successful,omitempty"`
	Strategy           string    `json:"strategy,omitempty"`
	AsOf               time.Time `json:"as_of,omitempty"`
}

type EndpointPoolRank struct {
	Endpoint            string    `json:"endpoint"`
	Score               float64   `json:"score"`
	Quality             string    `json:"quality"`
	SuccessRate         float64   `json:"success_rate_pct"`
	QuotaPct            float64   `json:"quota_pct,omitempty"`
	QuotaHeadroom       int64     `json:"quota_headroom,omitempty"`
	QuotaHeadroomPct    float64   `json:"quota_headroom_pct,omitempty"`
	QuotaSafetyBuffer   int64     `json:"quota_safety_buffer,omitempty"`
	QuotaGuarded        bool      `json:"quota_guarded"`
	QuotaResetAt        time.Time `json:"quota_reset_at,omitempty"`
	LatencyMs           float64   `json:"latency_ms,omitempty"`
	JitterMs            float64   `json:"jitter_ms,omitempty"`
	PacketLossPct       float64   `json:"packet_loss_pct,omitempty"`
	RecentFailure       bool      `json:"recent_failure"`
	HealthState         string    `json:"health_state"`
	CircuitOpen         bool      `json:"circuit_open"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	LoadPct             float64   `json:"load_pct,omitempty"`
	Weight              float64   `json:"weight"`
	Eligible            bool      `json:"eligible"`
}

type EndpointPoolPlan struct {
	Ranked                []EndpointPoolRank `json:"ranked"`
	DispatchOrder         []string           `json:"dispatch_order"`
	WarmPool              int                `json:"warm_pool"`
	PreferredEndpoint     string             `json:"preferred_endpoint,omitempty"`
	ReusedPreviousSuccess bool               `json:"reused_previous_success"`
	DiversityApplied      bool               `json:"diversity_applied"`
	SelectionBasis        []string           `json:"selection_basis"`
}

// BuildEndpointPoolPlan preserves the original planner contract. Callers that
// want deterministic diversity or a remembered-success hint can use
// BuildEndpointPoolPlanWithOptions.
func BuildEndpointPoolPlan(items []EndpointPoolObservation) (EndpointPoolPlan, error) {
	return BuildEndpointPoolPlanWithOptions(items, EndpointPoolOptions{})
}

// BuildEndpointPoolPlanWithOptions ranks relay/proxy endpoints using observed
// success, latency, quota, recent-failure, jitter, and loss evidence. It never
// performs network I/O and never makes an unobserved endpoint eligible.
//
// Jitter and loss are penalty-only signals so existing callers that do not
// provide them retain the pre-convergence score. Deterministic diversification
// is restricted to score bands no wider than endpointDiversityBand, preventing
// a scope seed from promoting a materially worse endpoint over a better one.
func BuildEndpointPoolPlanWithOptions(items []EndpointPoolObservation, options EndpointPoolOptions) (EndpointPoolPlan, error) {
	if len(items) == 0 || len(items) > 1000 {
		return EndpointPoolPlan{}, fmt.Errorf("endpoint pool size must be between 1 and 1000")
	}
	options.Scope = strings.TrimSpace(options.Scope)
	options.PreviousSuccessful = strings.TrimSpace(options.PreviousSuccessful)
	options.Strategy = strings.ToLower(strings.TrimSpace(options.Strategy))
	if options.Strategy == "" {
		options.Strategy = "quality-first"
	}
	switch options.Strategy {
	case "quality-first", "least-loaded", "weighted-quality", "sticky":
	default:
		return EndpointPoolPlan{}, fmt.Errorf("unsupported endpoint strategy %q", options.Strategy)
	}
	asOf := options.AsOf
	if asOf.IsZero() {
		asOf = time.Now()
	}
	if len(options.Scope) > 256 {
		return EndpointPoolPlan{}, fmt.Errorf("endpoint selection scope must be at most 256 characters")
	}
	if len(options.PreviousSuccessful) > 512 {
		return EndpointPoolPlan{}, fmt.Errorf("previous successful endpoint is too long")
	}

	seen := map[string]struct{}{}
	ranks := make([]EndpointPoolRank, 0, len(items))
	for _, o := range items {
		ep := strings.TrimSpace(o.Endpoint)
		if ep == "" || len(ep) > 512 {
			return EndpointPoolPlan{}, fmt.Errorf("invalid endpoint")
		}
		if _, ok := seen[ep]; ok {
			return EndpointPoolPlan{}, fmt.Errorf("duplicate endpoint %q", ep)
		}
		seen[ep] = struct{}{}
		health := strings.ToLower(strings.TrimSpace(o.HealthState))
		if health == "" {
			health = "unknown"
		}
		if health != "unknown" && health != "healthy" && health != "degraded" && health != "unhealthy" {
			return EndpointPoolPlan{}, fmt.Errorf("invalid health state for %s", ep)
		}
		if o.Successes < 0 || o.Failures < 0 || o.ConsecutiveFailures < 0 ||
			o.LatencyMs < 0 || o.LatencyMs > 120000 ||
			o.JitterMs < 0 || o.JitterMs > 120000 ||
			o.PacketLossPct < 0 || o.PacketLossPct > 100 ||
			o.RemainingQuota < 0 || o.QuotaLimit < 0 || o.QuotaSafetyBuffer < 0 ||
			o.Capacity < 0 || o.InFlight < 0 || (o.Capacity > 0 && o.InFlight > o.Capacity) ||
			o.Weight < 0 || o.Weight > 100 ||
			(o.QuotaLimit > 0 && (o.RemainingQuota > o.QuotaLimit || o.QuotaSafetyBuffer > o.QuotaLimit)) ||
			(o.QuotaLimit == 0 && o.QuotaSafetyBuffer > 0) {
			return EndpointPoolPlan{}, fmt.Errorf("invalid metrics for %s", ep)
		}

		attempts := o.Successes + o.Failures
		successRate := 50.0
		if attempts > 0 {
			successRate = float64(o.Successes) / float64(attempts) * 100
		}

		latencyScore := 15.0
		if o.LatencyMs > 0 {
			latencyScore = 30 * math.Max(0, 1-math.Min(o.LatencyMs, 3000)/3000)
		}
		quotaScore := 10.0
		quotaPct := 0.0
		quotaHeadroom := int64(0)
		quotaHeadroomPct := 0.0
		quotaGuarded := false
		if o.QuotaLimit > 0 {
			quotaPct = float64(o.RemainingQuota) / float64(o.QuotaLimit) * 100
			quotaHeadroom = o.RemainingQuota - o.QuotaSafetyBuffer
			if quotaHeadroom < 0 {
				quotaHeadroom = 0
			}
			quotaHeadroomPct = float64(quotaHeadroom) / float64(o.QuotaLimit) * 100
			quotaScore = 20 * quotaHeadroomPct / 100
			quotaGuarded = o.RemainingQuota <= o.QuotaSafetyBuffer
		}

		recentFailure := !o.LastFailed.IsZero() && (o.LastSucceeded.IsZero() || o.LastFailed.After(o.LastSucceeded))
		score := successRate*0.5 + latencyScore + quotaScore
		if recentFailure {
			score -= 15
		}
		// Temporal instability and loss are additive negative evidence. They do
		// not grant eligibility and they cannot improve an endpoint's score.
		if o.JitterMs > 0 {
			score -= 15 * math.Min(o.JitterMs, 1000) / 1000
		}
		if o.PacketLossPct > 0 {
			score -= 30 * o.PacketLossPct / 100
		}
		if health == "degraded" {
			score -= endpointDiversityBand
		}
		circuitOpen := o.ConsecutiveFailures >= 3 && (o.CooldownUntil.IsZero() || o.CooldownUntil.After(asOf))
		loadPct := 0.0
		if o.Capacity > 0 {
			loadPct = float64(o.InFlight) / float64(o.Capacity) * 100
		}
		weight := o.Weight
		if weight == 0 {
			weight = 1
		}
		if o.Disabled || health == "unhealthy" || circuitOpen || quotaGuarded {
			score = 0
		}
		score = math.Max(0, math.Min(score, 100))

		quality := "failed"
		switch {
		case o.Disabled:
			quality = "disabled"
		case health == "unhealthy":
			quality = "unhealthy"
		case circuitOpen:
			quality = "circuit-open"
		case quotaGuarded:
			quality = "quota-guarded"
		case attempts == 0:
			quality = "unknown"
		case score >= 85:
			quality = "excellent"
		case score >= 70:
			quality = "good"
		case score >= 50:
			quality = "fair"
		case score >= 25:
			quality = "poor"
		}
		eligible := !o.Disabled && health != "unhealthy" && !circuitOpen && !quotaGuarded && attempts > 0 && o.Successes > 0 && (o.QuotaLimit == 0 || o.RemainingQuota > o.QuotaSafetyBuffer) && (o.Capacity == 0 || o.InFlight < o.Capacity) && quality != "failed"
		ranks = append(ranks, EndpointPoolRank{
			Endpoint:            ep,
			Score:               roundEndpoint2(score),
			Quality:             quality,
			SuccessRate:         roundEndpoint2(successRate),
			QuotaPct:            roundEndpoint2(quotaPct),
			QuotaHeadroom:       quotaHeadroom,
			QuotaHeadroomPct:    roundEndpoint2(quotaHeadroomPct),
			QuotaSafetyBuffer:   o.QuotaSafetyBuffer,
			QuotaGuarded:        quotaGuarded,
			QuotaResetAt:        o.QuotaResetAt,
			LatencyMs:           o.LatencyMs,
			JitterMs:            o.JitterMs,
			PacketLossPct:       o.PacketLossPct,
			RecentFailure:       recentFailure,
			HealthState:         health,
			CircuitOpen:         circuitOpen,
			ConsecutiveFailures: o.ConsecutiveFailures,
			LoadPct:             roundEndpoint2(loadPct),
			Weight:              weight,
			Eligible:            eligible,
		})
	}

	sort.SliceStable(ranks, func(i, j int) bool {
		if ranks[i].Eligible != ranks[j].Eligible {
			return ranks[i].Eligible
		}
		if ranks[i].Score == ranks[j].Score {
			return ranks[i].Endpoint < ranks[j].Endpoint
		}
		return ranks[i].Score > ranks[j].Score
	})

	eligible := make([]EndpointPoolRank, 0, len(ranks))
	for _, rank := range ranks {
		if rank.Eligible {
			eligible = append(eligible, rank)
		}
	}

	order, diversityApplied := strategyEndpointOrder(eligible, options)
	reusedPrevious := false
	if options.PreviousSuccessful != "" && len(eligible) > 0 && (options.Strategy == "sticky" || options.Strategy == "quality-first") {
		bestScore := eligible[0].Score
		for i, endpoint := range order {
			if endpoint != options.PreviousSuccessful {
				continue
			}
			previousScore := endpointRankScore(eligible, endpoint)
			if bestScore-previousScore > endpointDiversityBand {
				break
			}
			copy(order[1:i+1], order[:i])
			order[0] = endpoint
			reusedPrevious = i > 0
			break
		}
	}

	warm := len(order)
	if warm > 16 {
		warm = 16
	}
	if warm > 0 && warm < 3 {
		warm = 3
	}
	if warm > len(order) {
		warm = len(order)
	}

	basis := []string{"observed-success", "latency", "quota", "recent-failure"}
	if anyEndpointMetric(items, func(o EndpointPoolObservation) bool { return o.QuotaSafetyBuffer > 0 }) {
		basis = append(basis, "quota-safety-buffer")
	}
	if anyEndpointMetric(items, func(o EndpointPoolObservation) bool { return !o.QuotaResetAt.IsZero() }) {
		basis = append(basis, "quota-reset-evidence")
	}
	if anyEndpointMetric(items, func(o EndpointPoolObservation) bool {
		return o.HealthState != "" || o.ConsecutiveFailures > 0 || !o.CooldownUntil.IsZero()
	}) {
		basis = append(basis, "health-circuit")
	}
	if anyEndpointMetric(items, func(o EndpointPoolObservation) bool { return o.Capacity > 0 || o.InFlight > 0 || o.Weight > 0 }) {
		basis = append(basis, "capacity-load")
	}
	if options.Strategy != "quality-first" {
		basis = append(basis, options.Strategy)
	}
	if anyEndpointMetric(items, func(o EndpointPoolObservation) bool { return o.JitterMs > 0 }) {
		basis = append(basis, "jitter")
	}
	if anyEndpointMetric(items, func(o EndpointPoolObservation) bool { return o.PacketLossPct > 0 }) {
		basis = append(basis, "packet-loss")
	}
	if options.Scope != "" {
		basis = append(basis, "deterministic-near-equal-diversity")
	}
	if reusedPrevious {
		basis = append(basis, "last-known-good")
	}

	preferred := ""
	if len(order) > 0 {
		preferred = order[0]
	}
	return EndpointPoolPlan{
		Ranked:                ranks,
		DispatchOrder:         order,
		WarmPool:              warm,
		PreferredEndpoint:     preferred,
		ReusedPreviousSuccess: reusedPrevious,
		DiversityApplied:      diversityApplied,
		SelectionBasis:        basis,
	}, nil
}

func strategyEndpointOrder(ranks []EndpointPoolRank, options EndpointPoolOptions) ([]string, bool) {
	if len(ranks) == 0 {
		return []string{}, false
	}
	// Secondary strategies may reorder only inside the same five-point quality
	// band. The target's quality evidence remains the primary authority.
	ordered := append([]EndpointPoolRank(nil), ranks...)
	changed := false
	for start := 0; start < len(ordered); {
		end := start + 1
		for end < len(ordered) && ordered[start].Score-ordered[end].Score <= endpointDiversityBand {
			end++
		}
		band := ordered[start:end]
		switch options.Strategy {
		case "least-loaded":
			sort.SliceStable(band, func(i, j int) bool {
				if band[i].LoadPct == band[j].LoadPct {
					return band[i].Endpoint < band[j].Endpoint
				}
				return band[i].LoadPct < band[j].LoadPct
			})
		case "weighted-quality":
			sort.SliceStable(band, func(i, j int) bool {
				if band[i].Weight == band[j].Weight {
					return band[i].Endpoint < band[j].Endpoint
				}
				return band[i].Weight > band[j].Weight
			})
		}
		start = end
	}
	base, diversity := diverseEndpointOrder(ordered, options.Scope)
	for i := range base {
		if base[i] != ranks[i].Endpoint {
			changed = true
			break
		}
	}
	return base, diversity || changed
}

func diverseEndpointOrder(ranks []EndpointPoolRank, scope string) ([]string, bool) {
	if len(ranks) == 0 {
		return []string{}, false
	}
	order := make([]string, 0, len(ranks))
	diversityApplied := false
	for start := 0; start < len(ranks); {
		end := start + 1
		for end < len(ranks) && ranks[start].Score-ranks[end].Score <= endpointDiversityBand {
			end++
		}
		band := ranks[start:end]
		rotation := 0
		if scope != "" && len(band) > 1 {
			rotation = int(stableScopeHash(scope, band[0].Quality) % uint64(len(band)))
			diversityApplied = diversityApplied || rotation != 0
		}
		for offset := 0; offset < len(band); offset++ {
			order = append(order, band[(rotation+offset)%len(band)].Endpoint)
		}
		start = end
	}
	return order, diversityApplied
}

func endpointRankScore(ranks []EndpointPoolRank, endpoint string) float64 {
	for _, rank := range ranks {
		if rank.Endpoint == endpoint {
			return rank.Score
		}
	}
	return math.Inf(-1)
}

func stableScopeHash(scope, quality string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(scope))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(quality))
	return h.Sum64()
}

func anyEndpointMetric(items []EndpointPoolObservation, predicate func(EndpointPoolObservation) bool) bool {
	for _, item := range items {
		if predicate(item) {
			return true
		}
	}
	return false
}

func roundEndpoint2(value float64) float64 {
	return math.Round(value*100) / 100
}
