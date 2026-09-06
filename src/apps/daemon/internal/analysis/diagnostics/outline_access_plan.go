package diagnostics

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

const maxOutlineAccessCandidateBytes = 8192

type OutlineAccessPlanRequest struct {
	Candidate string `json:"candidate"`
}

type OutlineAccessPlan struct {
	Kind              string   `json:"kind"`
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	InviteUnwrapped   bool     `json:"invite_unwrapped"`
	RemoteConfigURL   string   `json:"remote_config_url,omitempty"`
	RemoteFetchNeeded bool     `json:"remote_fetch_needed"`
	StaticValid       bool     `json:"static_valid"`
	Activatable       bool     `json:"activatable"`
	CompatibleCores   []string `json:"compatible_cores,omitempty"`
	PerformsNetworkIO bool     `json:"performs_network_io"`
	PersistsSecret    bool     `json:"persists_secret"`
	Invariants        []string `json:"invariants"`
	Warnings          []string `json:"warnings,omitempty"`
}

func BuildOutlineAccessPlan(req OutlineAccessPlanRequest) (OutlineAccessPlan, error) {
	raw := strings.TrimSpace(req.Candidate)
	if raw == "" || len(raw) > maxOutlineAccessCandidateBytes {
		return OutlineAccessPlan{}, fmt.Errorf("candidate is required and must not exceed %d bytes", maxOutlineAccessCandidateBytes)
	}
	candidate, unwrapped := unwrapOutlineInviteCandidate(raw)
	h := sha256.Sum256([]byte(candidate))
	plan := OutlineAccessPlan{FingerprintSHA256: fmt.Sprintf("%x", h[:]), InviteUnwrapped: unwrapped, PerformsNetworkIO: false, PersistsSecret: false,
		Invariants: []string{
			"access-key material is represented by a SHA-256 fingerprint in planner output rather than echoed back as a credential",
			"static ss:// keys are validated by the canonical proxy parser and external-core compatibility owner",
			"dynamic ssconf:// keys are only converted into an HTTPS fetch proposal; the planner never performs the fetch",
			"dynamic fetches must later pass canonical guarded-egress DNS/IP/redirect validation before network access",
			"invite unwrapping is local parsing only and cannot activate, persist, or connect a profile",
		},
	}
	lower := strings.ToLower(candidate)
	if strings.HasPrefix(lower, "ss://") {
		cfg, err := proxyconfig.ParseProxyURI(candidate)
		if err != nil || cfg == nil || cfg.Protocol != proxyconfig.ProtocolShadowsocks {
			if err == nil {
				err = fmt.Errorf("not a Shadowsocks key")
			}
			return OutlineAccessPlan{}, fmt.Errorf("invalid Outline static access key: %w", err)
		}
		compat := proxyconfig.EvaluateExternalCoreCompatibility(cfg)
		plan.Kind, plan.StaticValid, plan.Activatable, plan.CompatibleCores = "static", true, compat.Activatable, compat.Cores
		if !compat.Activatable {
			plan.Warnings = append(plan.Warnings, compat.Reason)
		}
		return plan, nil
	}
	if strings.HasPrefix(lower, "ssconf://") {
		u, err := url.Parse(candidate)
		if err != nil {
			return OutlineAccessPlan{}, fmt.Errorf("invalid dynamic access key: %w", err)
		}
		if u.User != nil || u.Hostname() == "" || u.Fragment != "" {
			return OutlineAccessPlan{}, fmt.Errorf("dynamic access key must not contain authority credentials or fragments")
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil && (!ip.IsGlobalUnicast() || ip.IsPrivate()) {
			return OutlineAccessPlan{}, fmt.Errorf("dynamic access key IP literal must be public global-unicast")
		}
		if strings.EqualFold(u.Hostname(), "localhost") {
			return OutlineAccessPlan{}, fmt.Errorf("dynamic access key localhost target is not admitted")
		}
		u.Scheme = "https"
		plan.Kind, plan.RemoteFetchNeeded, plan.RemoteConfigURL = "dynamic", true, u.String()
		plan.Warnings = append(plan.Warnings, "remote configuration is unresolved planning evidence until canonical egress validates and fetches it")
		return plan, nil
	}
	return OutlineAccessPlan{}, fmt.Errorf("candidate must resolve to ss:// or ssconf:// Outline access-key semantics")
}

func unwrapOutlineInviteCandidate(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment == "" {
		return raw, false
	}
	frag := u.Fragment
	if decoded, err := url.PathUnescape(frag); err == nil {
		frag = decoded
	}
	idx := strings.Index(strings.ToLower(frag), "ss://")
	if idx < 0 {
		return raw, false
	}
	return frag[idx:], true
}
