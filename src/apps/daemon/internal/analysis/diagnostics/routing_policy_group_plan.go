package diagnostics

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
)

const maxRoutingPolicyCandidates = 128

type RoutingPolicyCandidate struct {
	Name      string  `json:"name"`
	Healthy   bool    `json:"healthy"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Weight    float64 `json:"weight,omitempty"`
}

type RoutingPolicyGroupRequest struct {
	Mode       string                   `json:"mode"`
	Candidates []RoutingPolicyCandidate `json:"candidates"`
	Selected   string                   `json:"selected,omitempty"`
	Scope      string                   `json:"scope,omitempty"`
}

type RoutingPolicyShare struct {
	Name     string  `json:"name"`
	Weight   float64 `json:"weight"`
	SharePct float64 `json:"share_pct"`
}

type RoutingPolicyGroupPlan struct {
	Mode              string               `json:"mode"`
	Preferred         string               `json:"preferred,omitempty"`
	DispatchOrder     []string             `json:"dispatch_order"`
	Skipped           []string             `json:"skipped"`
	Shares            []RoutingPolicyShare `json:"shares,omitempty"`
	UsesObservedState bool                 `json:"uses_observed_state"`
	PerformsNetworkIO bool                 `json:"performs_network_io"`
	InstallsPolicy    bool                 `json:"installs_policy"`
	Invariants        []string             `json:"invariants"`
}

// BuildRoutingPolicyGroupPlan translates common proxy-group intent into a
// bounded, read-only target-native selection preview. Unlike donor url-test
// groups it never contacts a probe URL; latency-auto can only consume latency
// evidence already supplied by the caller.
func BuildRoutingPolicyGroupPlan(req RoutingPolicyGroupRequest) (RoutingPolicyGroupPlan, error) {
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	switch mode {
	case "manual-select", "latency-auto", "fallback", "load-balance":
	default:
		return RoutingPolicyGroupPlan{}, fmt.Errorf("unsupported routing policy-group mode %q", req.Mode)
	}
	if len(req.Candidates) == 0 || len(req.Candidates) > maxRoutingPolicyCandidates {
		return RoutingPolicyGroupPlan{}, fmt.Errorf("routing policy-group candidate count must be 1..%d", maxRoutingPolicyCandidates)
	}
	if len(req.Scope) > 256 {
		return RoutingPolicyGroupPlan{}, fmt.Errorf("routing policy-group scope must be at most 256 bytes")
	}

	candidates := append([]RoutingPolicyCandidate(nil), req.Candidates...)
	seen := map[string]bool{}
	byName := map[string]RoutingPolicyCandidate{}
	for i := range candidates {
		candidates[i].Name = strings.TrimSpace(candidates[i].Name)
		if candidates[i].Name == "" || len(candidates[i].Name) > 128 || seen[candidates[i].Name] {
			return RoutingPolicyGroupPlan{}, fmt.Errorf("invalid or duplicate routing policy candidate %q", candidates[i].Name)
		}
		if candidates[i].LatencyMS < 0 || candidates[i].LatencyMS > 120000 || math.IsNaN(candidates[i].LatencyMS) || math.IsInf(candidates[i].LatencyMS, 0) {
			return RoutingPolicyGroupPlan{}, fmt.Errorf("invalid latency for routing policy candidate %q", candidates[i].Name)
		}
		if candidates[i].Weight < 0 || candidates[i].Weight > 1000 || math.IsNaN(candidates[i].Weight) || math.IsInf(candidates[i].Weight, 0) {
			return RoutingPolicyGroupPlan{}, fmt.Errorf("invalid weight for routing policy candidate %q", candidates[i].Name)
		}
		seen[candidates[i].Name] = true
		byName[candidates[i].Name] = candidates[i]
	}

	plan := RoutingPolicyGroupPlan{
		Mode:              mode,
		DispatchOrder:     []string{},
		Skipped:           []string{},
		UsesObservedState: mode != "manual-select",
		Invariants: []string{
			"policy-group selection is a read-only preview and installs no routing policy",
			"latency-auto uses caller-supplied observations only and performs no remote probe",
			"fallback preserves declared candidate order while skipping unhealthy evidence",
			"load-balance is deterministic for the same candidate set and scope",
			"unhealthy candidates never gain automatic dispatch authority",
		},
	}

	for _, candidate := range candidates {
		if !candidate.Healthy {
			plan.Skipped = append(plan.Skipped, candidate.Name)
		}
	}

	switch mode {
	case "manual-select":
		selected := strings.TrimSpace(req.Selected)
		candidate, ok := byName[selected]
		if !ok || selected == "" {
			return RoutingPolicyGroupPlan{}, fmt.Errorf("manual-select requires selected candidate from the admitted set")
		}
		if !candidate.Healthy {
			return RoutingPolicyGroupPlan{}, fmt.Errorf("manual-select candidate %q is explicitly unhealthy", selected)
		}
		plan.Preferred = selected
		plan.DispatchOrder = []string{selected}

	case "latency-auto":
		eligible := make([]RoutingPolicyCandidate, 0, len(candidates))
		for _, candidate := range candidates {
			if candidate.Healthy && candidate.LatencyMS > 0 {
				eligible = append(eligible, candidate)
			}
		}
		if len(eligible) == 0 {
			return RoutingPolicyGroupPlan{}, fmt.Errorf("latency-auto requires at least one healthy candidate with observed latency")
		}
		sort.SliceStable(eligible, func(i, j int) bool {
			if eligible[i].LatencyMS == eligible[j].LatencyMS {
				return eligible[i].Name < eligible[j].Name
			}
			return eligible[i].LatencyMS < eligible[j].LatencyMS
		})
		for _, candidate := range eligible {
			plan.DispatchOrder = append(plan.DispatchOrder, candidate.Name)
		}
		plan.Preferred = plan.DispatchOrder[0]

	case "fallback":
		for _, candidate := range candidates {
			if candidate.Healthy {
				plan.DispatchOrder = append(plan.DispatchOrder, candidate.Name)
			}
		}
		if len(plan.DispatchOrder) == 0 {
			return RoutingPolicyGroupPlan{}, fmt.Errorf("fallback has no healthy candidate")
		}
		plan.Preferred = plan.DispatchOrder[0]

	case "load-balance":
		eligible := make([]RoutingPolicyCandidate, 0, len(candidates))
		for _, candidate := range candidates {
			if candidate.Healthy {
				if candidate.Weight == 0 {
					candidate.Weight = 1
				}
				eligible = append(eligible, candidate)
			}
		}
		if len(eligible) == 0 {
			return RoutingPolicyGroupPlan{}, fmt.Errorf("load-balance has no healthy candidate")
		}
		sort.SliceStable(eligible, func(i, j int) bool {
			hi := routingPolicyHash(req.Scope, eligible[i].Name)
			hj := routingPolicyHash(req.Scope, eligible[j].Name)
			if hi == hj {
				return eligible[i].Name < eligible[j].Name
			}
			return hi < hj
		})
		total := 0.0
		for _, candidate := range eligible {
			total += candidate.Weight
		}
		for _, candidate := range eligible {
			plan.DispatchOrder = append(plan.DispatchOrder, candidate.Name)
			plan.Shares = append(plan.Shares, RoutingPolicyShare{Name: candidate.Name, Weight: candidate.Weight, SharePct: math.Round((candidate.Weight/total*100)*100) / 100})
		}
		plan.Preferred = plan.DispatchOrder[0]
	}

	return plan, nil
}

func routingPolicyHash(scope, name string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.TrimSpace(scope)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(name))
	return h.Sum64()
}
