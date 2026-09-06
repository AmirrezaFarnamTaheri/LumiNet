package diagnostics

import (
	"fmt"
	"strings"
)

type TorBootstrapEvidenceRequest struct {
	ControlConnected    bool   `json:"control_connected"`
	Authenticated       bool   `json:"authenticated"`
	SafeCookieAvailable bool   `json:"safe_cookie_available"`
	NetworkEnabled      bool   `json:"network_enabled"`
	BootstrapProgress   int    `json:"bootstrap_progress"`
	BootstrapTag        string `json:"bootstrap_tag,omitempty"`
	BootstrapSummary    string `json:"bootstrap_summary,omitempty"`
	CircuitEstablished  bool   `json:"circuit_established"`
	SocksListeners      int    `json:"socks_listeners"`
	StreamIsolation     bool   `json:"stream_isolation"`
}

type TorBootstrapEvidencePlan struct {
	State                string   `json:"state"`
	Ready                bool     `json:"ready"`
	BootstrapProgress    int      `json:"bootstrap_progress"`
	AuthenticationMethod string   `json:"authentication_method"`
	Warnings             []string `json:"warnings"`
	ControlsTor          bool     `json:"controls_tor"`
	ReadsCookieBytes     bool     `json:"reads_cookie_bytes"`
	PerformsNetworkIO    bool     `json:"performs_network_io"`
	ReadOnly             bool     `json:"read_only"`
	Invariants           []string `json:"invariants"`
}

func BuildTorBootstrapEvidencePlan(req TorBootstrapEvidenceRequest) (TorBootstrapEvidencePlan, error) {
	if req.BootstrapProgress < 0 || req.BootstrapProgress > 100 {
		return TorBootstrapEvidencePlan{}, fmt.Errorf("bootstrap progress must be 0..100")
	}
	if req.SocksListeners < 0 || req.SocksListeners > 32 {
		return TorBootstrapEvidencePlan{}, fmt.Errorf("SOCKS listener count must be 0..32")
	}
	if len(strings.TrimSpace(req.BootstrapTag)) > 64 || len(strings.TrimSpace(req.BootstrapSummary)) > 512 {
		return TorBootstrapEvidencePlan{}, fmt.Errorf("bootstrap evidence text exceeds bound")
	}
	state := "ready"
	ready := true
	switch {
	case !req.ControlConnected:
		state, ready = "control-unavailable", false
	case !req.Authenticated:
		state, ready = "authentication-required", false
	case !req.NetworkEnabled:
		state, ready = "network-disabled", false
	case req.BootstrapProgress < 100:
		state, ready = "bootstrapping", false
	case !req.CircuitEstablished:
		state, ready = "circuit-pending", false
	case req.SocksListeners == 0:
		state, ready = "socks-unavailable", false
	}
	auth := "authenticated-control"
	if req.SafeCookieAvailable {
		auth = "safecookie-capable"
	}
	if !req.Authenticated {
		auth = "not-authenticated"
	}
	warnings := []string{}
	if ready && !req.StreamIsolation {
		warnings = append(warnings, "Tor is ready but stream isolation evidence is absent")
	}
	return TorBootstrapEvidencePlan{
		State: state, Ready: ready, BootstrapProgress: req.BootstrapProgress, AuthenticationMethod: auth, Warnings: warnings,
		ControlsTor: false, ReadsCookieBytes: false, PerformsNetworkIO: false, ReadOnly: true,
		Invariants: []string{
			"SAFECOOKIE capability is represented as evidence only; cookie bytes and authentication challenges are never accepted by this planner",
			"ready requires authenticated control evidence, enabled network, completed bootstrap, a circuit, and at least one SOCKS listener",
			"stream isolation is reported separately from bootstrap readiness",
			"the planner never launches Tor, rotates circuits, changes DisableNetwork, or opens listeners",
		},
	}, nil
}
