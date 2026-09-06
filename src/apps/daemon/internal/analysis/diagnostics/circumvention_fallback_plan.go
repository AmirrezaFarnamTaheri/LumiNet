package diagnostics

import (
	"fmt"
	"strings"
)

const maxCircumventionTimeoutSeconds = 300

type CircumventionFallbackRequest struct {
	Enabled                bool   `json:"enabled"`
	CurrentTransport       string `json:"current_transport"`
	BootstrapProgress      int    `json:"bootstrap_progress"`
	SecondsSinceProgress   int    `json:"seconds_since_progress"`
	TimeoutSeconds         int    `json:"timeout_seconds"`
	CustomBridgesAvailable bool   `json:"custom_bridges_available,omitempty"`
}

type CircumventionFallbackPlan struct {
	CurrentTransport   string   `json:"current_transport"`
	NextTransport      string   `json:"next_transport,omitempty"`
	Action             string   `json:"action"`
	Terminal           bool     `json:"terminal"`
	ResetDeadline      bool     `json:"reset_deadline"`
	MaximumTransitions int      `json:"maximum_transitions"`
	PerformsNetworkIO  bool     `json:"performs_network_io"`
	StartsTransport    bool     `json:"starts_transport"`
	MutatesPreferences bool     `json:"mutates_preferences"`
	Reasons            []string `json:"reasons"`
	Invariants         []string `json:"invariants"`
}

func BuildCircumventionFallbackPlan(req CircumventionFallbackRequest) (CircumventionFallbackPlan, error) {
	current := strings.ToLower(strings.TrimSpace(req.CurrentTransport))
	if current == "" {
		current = "direct"
	}
	switch current {
	case "direct", "snowflake", "custom", "obfs4", "meek", "webtunnel", "dnstt":
	default:
		return CircumventionFallbackPlan{}, fmt.Errorf("unsupported current transport %q", req.CurrentTransport)
	}
	if req.BootstrapProgress < 0 || req.BootstrapProgress > 100 {
		return CircumventionFallbackPlan{}, fmt.Errorf("bootstrap_progress must be 0..100")
	}
	if req.SecondsSinceProgress < 0 || req.SecondsSinceProgress > 3600 {
		return CircumventionFallbackPlan{}, fmt.Errorf("seconds_since_progress must be 0..3600")
	}
	timeout := req.TimeoutSeconds
	if timeout == 0 {
		timeout = 30
	}
	if timeout < 5 || timeout > maxCircumventionTimeoutSeconds {
		return CircumventionFallbackPlan{}, fmt.Errorf("timeout_seconds must be 5..%d", maxCircumventionTimeoutSeconds)
	}
	plan := CircumventionFallbackPlan{
		CurrentTransport: current, MaximumTransitions: 3, PerformsNetworkIO: false, StartsTransport: false,
		MutatesPreferences: false,
		Invariants: []string{
			"progress extends the current attempt instead of consuming a fallback transition",
			"the bounded smart-connect chain is direct -> snowflake -> custom-or-obfs4 -> obfs4 -> fail",
			"fallback selection never starts or stops a transport and never edits persisted preferences",
			"custom bridge fallback is eligible only when caller-supplied bridge availability evidence exists",
			"a completed bootstrap is terminal success and disables fallback",
		},
	}
	if !req.Enabled {
		plan.Action, plan.Terminal = "disabled", true
		plan.Reasons = append(plan.Reasons, "automatic circumvention fallback is disabled")
		return plan, nil
	}
	if req.BootstrapProgress >= 100 {
		plan.Action, plan.Terminal = "complete", true
		plan.Reasons = append(plan.Reasons, "bootstrap reached 100 percent")
		return plan, nil
	}
	if req.SecondsSinceProgress < timeout {
		plan.Action, plan.ResetDeadline = "wait", true
		plan.Reasons = append(plan.Reasons, "progress deadline has not expired")
		return plan, nil
	}
	plan.Action = "fallback"
	switch current {
	case "direct":
		plan.NextTransport = "snowflake"
	case "snowflake":
		if req.CustomBridgesAvailable {
			plan.NextTransport = "custom"
		} else {
			plan.NextTransport = "obfs4"
		}
	case "custom":
		plan.NextTransport = "obfs4"
	case "obfs4", "meek", "webtunnel", "dnstt":
		plan.Action, plan.Terminal = "fail", true
		plan.Reasons = append(plan.Reasons, "bounded fallback chain is exhausted")
	}
	if plan.NextTransport != "" {
		plan.Reasons = append(plan.Reasons, fmt.Sprintf("no progress for %d seconds; next bounded transport is %s", req.SecondsSinceProgress, plan.NextTransport))
	}
	return plan, nil
}
