package diagnostics

import (
	"fmt"
	"sort"
	"strings"
)

const maxTLSFingerprintCandidates = 16

type TLSFingerprintPolicyRequest struct {
	Candidates          []string `json:"candidates"`
	KnownGood           string   `json:"known_good,omitempty"`
	ReuseKnownGood      bool     `json:"reuse_known_good,omitempty"`
	MaxTrials           int      `json:"max_trials,omitempty"`
	RequiredALPN        []string `json:"required_alpn,omitempty"`
	AllowWeakCiphers    bool     `json:"allow_weak_ciphers,omitempty"`
	ECHRequired         bool     `json:"ech_required,omitempty"`
	QUICRequired        bool     `json:"quic_required,omitempty"`
	PerConnectionRotate bool     `json:"per_connection_rotate,omitempty"`
}

type TLSFingerprintPolicyPlan struct {
	OrderedProfiles []string `json:"ordered_profiles"`
	MaxTrials       int      `json:"max_trials"`
	ReuseKnownGood  bool     `json:"reuse_known_good"`
	RequiredALPN    []string `json:"required_alpn"`
	Warnings        []string `json:"warnings"`
	Invariants      []string `json:"invariants"`
	ReadOnly        bool     `json:"read_only"`
}

func supportedTLSFingerprintProfile(profile string) bool {
	switch profile {
	case "native", "chrome", "firefox", "edge", "safari", "randomized", "randomized-alpn", "randomized-noalpn":
		return true
	default:
		return false
	}
}

func BuildTLSFingerprintPolicyPlan(req TLSFingerprintPolicyRequest) (TLSFingerprintPolicyPlan, error) {
	if len(req.Candidates) == 0 || len(req.Candidates) > maxTLSFingerprintCandidates {
		return TLSFingerprintPolicyPlan{}, fmt.Errorf("TLS fingerprint candidate count must be between 1 and %d", maxTLSFingerprintCandidates)
	}
	if req.AllowWeakCiphers {
		return TLSFingerprintPolicyPlan{}, fmt.Errorf("weak TLS ciphers are not admissible")
	}
	maxTrials := req.MaxTrials
	if maxTrials == 0 {
		maxTrials = 4
	}
	if maxTrials < 1 || maxTrials > 8 {
		return TLSFingerprintPolicyPlan{}, fmt.Errorf("TLS fingerprint max_trials must be between 1 and 8")
	}

	seen := map[string]bool{}
	profiles := make([]string, 0, len(req.Candidates))
	for _, raw := range req.Candidates {
		profile := strings.ToLower(strings.TrimSpace(raw))
		if !supportedTLSFingerprintProfile(profile) {
			return TLSFingerprintPolicyPlan{}, fmt.Errorf("unsupported TLS fingerprint profile %q", raw)
		}
		if seen[profile] {
			continue
		}
		seen[profile] = true
		profiles = append(profiles, profile)
	}
	if len(profiles) == 0 {
		return TLSFingerprintPolicyPlan{}, fmt.Errorf("no unique TLS fingerprint profiles remain")
	}

	alpnSeen := map[string]bool{}
	alpn := make([]string, 0, len(req.RequiredALPN))
	for _, raw := range req.RequiredALPN {
		v := strings.ToLower(strings.TrimSpace(raw))
		switch v {
		case "h2", "http/1.1", "h3":
		default:
			return TLSFingerprintPolicyPlan{}, fmt.Errorf("unsupported ALPN %q", raw)
		}
		if !alpnSeen[v] {
			alpnSeen[v] = true
			alpn = append(alpn, v)
		}
	}
	sort.Strings(alpn)
	if req.QUICRequired && !alpnSeen["h3"] {
		return TLSFingerprintPolicyPlan{}, fmt.Errorf("QUIC fingerprint policy requires h3 ALPN evidence")
	}

	knownGood := strings.ToLower(strings.TrimSpace(req.KnownGood))
	if knownGood != "" && !seen[knownGood] {
		return TLSFingerprintPolicyPlan{}, fmt.Errorf("known_good profile %q is not in candidates", knownGood)
	}
	if req.ReuseKnownGood && knownGood != "" {
		ordered := []string{knownGood}
		for _, profile := range profiles {
			if profile != knownGood {
				ordered = append(ordered, profile)
			}
		}
		profiles = ordered
	}

	warnings := []string{}
	if req.PerConnectionRotate {
		warnings = append(warnings, "per-connection fingerprint rotation reduces consistency and should not replace reuse of an observed working profile")
	}
	if req.ECHRequired {
		warnings = append(warnings, "ECH capability must be verified by the live TLS owner; this plan does not synthesize ECH")
	}
	if len(profiles) > maxTrials {
		profiles = profiles[:maxTrials]
	}

	return TLSFingerprintPolicyPlan{
		OrderedProfiles: profiles,
		MaxTrials:       maxTrials,
		ReuseKnownGood:  req.ReuseKnownGood && knownGood != "",
		RequiredALPN:    alpn,
		Warnings:        warnings,
		Invariants: []string{
			"observed working fingerprints are reused before exploratory variants when requested",
			"weak ciphers are never enabled by fingerprint experimentation",
			"ALPN requirements must match the transport capability being tested",
			"fingerprint planning never grants certificate-trust or connection authority",
		},
		ReadOnly: true,
	}, nil
}
