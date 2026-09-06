package diagnostics

import (
	"fmt"
	"sort"
	"strings"
)

const maxTunnelReconnectAttempts = 20

type TunnelSafetyRequest struct {
	DesiredState          string   `json:"desired_state"`
	ObservedState         string   `json:"observed_state"`
	PersistedTargetState  string   `json:"persisted_target_state,omitempty"`
	LockdownMode          string   `json:"lockdown_mode,omitempty"`
	FirewallBlockApplied  *bool    `json:"firewall_block_applied,omitempty"`
	DNSGuardApplied       *bool    `json:"dns_guard_applied,omitempty"`
	QUICGuardApplied      *bool    `json:"quic_guard_applied,omitempty"`
	STUNGuardApplied      *bool    `json:"stun_guard_applied,omitempty"`
	DoHGuardApplied       *bool    `json:"doh_guard_applied,omitempty"`
	IPv6GuardApplied      *bool    `json:"ipv6_guard_applied,omitempty"`
	RequiredGuards        []string `json:"required_guards,omitempty"`
	AllowLAN              bool     `json:"allow_lan,omitempty"`
	ActionAfterDisconnect string   `json:"action_after_disconnect,omitempty"`
	ReconnectAttempt      int      `json:"reconnect_attempt,omitempty"`
	MaxReconnectAttempts  int      `json:"max_reconnect_attempts,omitempty"`
}

type TunnelSafetyPlan struct {
	DesiredState             string   `json:"desired_state"`
	EffectiveProtectionState string   `json:"effective_protection_state"`
	ObservedState            string   `json:"observed_state"`
	LockdownRequired         bool     `json:"lockdown_required"`
	FirewallBlockConfirmed   bool     `json:"firewall_block_confirmed"`
	DNSGuardConfirmed        bool     `json:"dns_guard_confirmed"`
	RequiredGuards           []string `json:"required_guards"`
	MissingOrFailedGuards    []string `json:"missing_or_failed_guards"`
	ReconnectAllowed         bool     `json:"reconnect_allowed"`
	NextAction               string   `json:"next_action"`
	Reasons                  []string `json:"reasons"`
	Invariants               []string `json:"invariants"`
	ReadOnly                 bool     `json:"read_only"`
	MutatesHostNetwork       bool     `json:"mutates_host_network"`
}

func normalizeTunnelRequiredGuards(raw []string) ([]string, error) {
	if len(raw) > 8 {
		return nil, fmt.Errorf("required_guards must contain at most 8 entries")
	}
	seen := map[string]bool{}
	out := []string{}
	for _, item := range raw {
		guard := strings.ToLower(strings.TrimSpace(item))
		switch guard {
		case "dns", "quic", "stun", "doh", "ipv6":
		default:
			return nil, fmt.Errorf("unsupported required tunnel guard %q", item)
		}
		if !seen[guard] {
			seen[guard] = true
			out = append(out, guard)
		}
	}
	sort.Strings(out)
	return out, nil
}

func tunnelGuardEvidence(req TunnelSafetyRequest, guard string) *bool {
	switch guard {
	case "dns":
		return req.DNSGuardApplied
	case "quic":
		return req.QUICGuardApplied
	case "stun":
		return req.STUNGuardApplied
	case "doh":
		return req.DoHGuardApplied
	case "ipv6":
		return req.IPv6GuardApplied
	default:
		return nil
	}
}

func BuildTunnelSafetyPlan(req TunnelSafetyRequest) (TunnelSafetyPlan, error) {
	requiredGuards, err := normalizeTunnelRequiredGuards(req.RequiredGuards)
	if err != nil {
		return TunnelSafetyPlan{}, err
	}
	desired := strings.ToLower(strings.TrimSpace(req.DesiredState))
	if desired == "" {
		desired = "unsecured"
	}
	if desired != "secured" && desired != "unsecured" {
		return TunnelSafetyPlan{}, fmt.Errorf("desired_state must be secured or unsecured")
	}
	observed := strings.ToLower(strings.TrimSpace(req.ObservedState))
	switch observed {
	case "disconnected", "connecting", "connected", "disconnecting", "error", "offline":
	default:
		return TunnelSafetyPlan{}, fmt.Errorf("observed_state must be disconnected, connecting, connected, disconnecting, error, or offline")
	}
	persisted := strings.ToLower(strings.TrimSpace(req.PersistedTargetState))
	if persisted == "" {
		persisted = "missing"
	}
	switch persisted {
	case "missing", "valid-secured", "valid-unsecured", "corrupt":
	default:
		return TunnelSafetyPlan{}, fmt.Errorf("persisted_target_state must be missing, valid-secured, valid-unsecured, or corrupt")
	}
	lockdown := strings.ToLower(strings.TrimSpace(req.LockdownMode))
	if lockdown == "" {
		lockdown = "auto"
	}
	switch lockdown {
	case "auto", "always", "when-disconnected", "off":
	default:
		return TunnelSafetyPlan{}, fmt.Errorf("lockdown_mode must be auto, always, when-disconnected, or off")
	}
	action := strings.ToLower(strings.TrimSpace(req.ActionAfterDisconnect))
	if action == "" {
		action = "nothing"
	}
	switch action {
	case "nothing", "block", "reconnect":
	default:
		return TunnelSafetyPlan{}, fmt.Errorf("action_after_disconnect must be nothing, block, or reconnect")
	}
	maxReconnect := req.MaxReconnectAttempts
	if maxReconnect == 0 {
		maxReconnect = 4
	}
	if maxReconnect < 0 || maxReconnect > maxTunnelReconnectAttempts {
		return TunnelSafetyPlan{}, fmt.Errorf("max_reconnect_attempts must be between 0 and %d", maxTunnelReconnectAttempts)
	}
	if req.ReconnectAttempt < 0 || req.ReconnectAttempt > maxReconnect {
		return TunnelSafetyPlan{}, fmt.Errorf("reconnect_attempt must be between 0 and max_reconnect_attempts")
	}

	plan := TunnelSafetyPlan{
		DesiredState:          desired,
		ObservedState:         observed,
		RequiredGuards:        requiredGuards,
		MissingOrFailedGuards: []string{},
		ReadOnly:              true,
		MutatesHostNetwork:    false,
		NextAction:            "observe",
		Invariants: []string{
			"the daemon security owner distinguishes desired secure state from observed tunnel state",
			"corrupt persisted secure-state intent fails closed to secured rather than defaulting open",
			"an error state is not called secure when the blocking firewall failed to apply",
			"reconnect is bounded and never replaces a required lockdown barrier",
			"LAN allowance does not implicitly disable DNS or firewall protection",
			"required QUIC, STUN, DoH, IPv6, and DNS leak guards are caller-supplied evidence and missing/false evidence degrades secured-state truth",
			"this planner never changes firewall, DNS, routes, proxy settings, or tunnel processes",
		},
	}
	if persisted == "corrupt" {
		plan.DesiredState = "secured"
		desired = "secured"
		plan.Reasons = append(plan.Reasons, "persisted target state is corrupt; fail-closed recovery treats the desired state as secured")
	} else if persisted == "valid-secured" && desired != "secured" {
		plan.Reasons = append(plan.Reasons, "caller desired state differs from persisted secured intent")
	} else if persisted == "valid-unsecured" && desired != "unsecured" {
		plan.Reasons = append(plan.Reasons, "caller desired state differs from persisted unsecured intent")
	}

	firewallKnown := req.FirewallBlockApplied != nil
	firewallApplied := firewallKnown && *req.FirewallBlockApplied
	dnsKnown := req.DNSGuardApplied != nil
	dnsApplied := dnsKnown && *req.DNSGuardApplied
	plan.FirewallBlockConfirmed = firewallApplied
	plan.DNSGuardConfirmed = dnsApplied
	for _, guard := range requiredGuards {
		evidence := tunnelGuardEvidence(req, guard)
		if evidence == nil || !*evidence {
			plan.MissingOrFailedGuards = append(plan.MissingOrFailedGuards, guard)
		}
	}

	disconnectedLike := observed == "disconnected" || observed == "disconnecting" || observed == "error" || observed == "offline"
	plan.LockdownRequired = lockdown == "always" || (lockdown == "when-disconnected" && disconnectedLike) || (lockdown == "auto" && desired == "secured" && disconnectedLike)
	if action == "block" && disconnectedLike {
		plan.LockdownRequired = true
	}

	switch {
	case desired == "unsecured" && observed == "disconnected" && !plan.LockdownRequired:
		plan.EffectiveProtectionState = "unsecured"
		plan.NextAction = "none"
	case observed == "connected" && desired == "secured":
		plan.EffectiveProtectionState = "secured-tunnel"
		plan.NextAction = "maintain"
		if dnsKnown && !dnsApplied {
			plan.EffectiveProtectionState = "degraded"
			plan.Reasons = append(plan.Reasons, "tunnel is connected but DNS guard evidence is false")
		}
		if len(plan.MissingOrFailedGuards) > 0 {
			plan.EffectiveProtectionState = "degraded"
			plan.Reasons = append(plan.Reasons, "tunnel is connected but required leak-guard evidence is missing or false: "+strings.Join(plan.MissingOrFailedGuards, ", "))
		}
	case plan.LockdownRequired && firewallApplied:
		plan.EffectiveProtectionState = "secured-lockdown"
		plan.NextAction = "maintain-block"
	case plan.LockdownRequired && !firewallApplied:
		plan.EffectiveProtectionState = "degraded-unsafe"
		plan.NextAction = "establish-block"
		if !firewallKnown {
			plan.Reasons = append(plan.Reasons, "lockdown is required but firewall-block evidence is unknown")
		} else {
			plan.Reasons = append(plan.Reasons, "lockdown is required but firewall blocking failed or is not applied")
		}
	case observed == "connecting" || observed == "disconnecting":
		plan.EffectiveProtectionState = "transitioning"
	case observed == "error":
		plan.EffectiveProtectionState = "degraded-unsafe"
		plan.Reasons = append(plan.Reasons, "tunnel entered error without confirmed blocking protection")
	case observed == "offline" && desired == "secured":
		plan.EffectiveProtectionState = "degraded-unsafe"
		plan.Reasons = append(plan.Reasons, "network is offline and no blocking protection is confirmed")
	default:
		plan.EffectiveProtectionState = "unsecured"
	}

	if action == "reconnect" && desired == "secured" && disconnectedLike && req.ReconnectAttempt < maxReconnect {
		plan.ReconnectAllowed = true
		if plan.NextAction == "observe" || plan.NextAction == "maintain-block" {
			plan.NextAction = "reconnect"
		}
	} else if action == "reconnect" && req.ReconnectAttempt >= maxReconnect {
		plan.Reasons = append(plan.Reasons, "reconnect budget is exhausted")
	}
	if req.AllowLAN && desired == "secured" {
		plan.Reasons = append(plan.Reasons, "LAN allowance is an explicit exception and must remain narrower than the tunnel/lockdown policy")
	}
	return plan, nil
}
