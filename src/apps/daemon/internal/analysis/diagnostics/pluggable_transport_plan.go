package diagnostics

import (
	"fmt"
	"strings"
)

const (
	maxPTFrontDomains = 32
	maxPTICEServers   = 32
	maxPTPeers        = 64
)

type PluggableTransportPlanRequest struct {
	Transport          string `json:"transport"`
	Platform           string `json:"platform"`
	ObservedState      string `json:"observed_state"`
	StateDirConfigured bool   `json:"state_dir_configured"`
	StateDirWritable   bool   `json:"state_dir_writable"`
	LoggingEnabled     bool   `json:"logging_enabled,omitempty"`
	UnsafeLogging      bool   `json:"unsafe_logging,omitempty"`
	OutboundProxyKind  string `json:"outbound_proxy_kind,omitempty"`
	LocalPort          int    `json:"local_port,omitempty"`
	MaxPeers           int    `json:"max_peers,omitempty"`
	FrontDomainCount   int    `json:"front_domain_count,omitempty"`
	ICEServerCount     int    `json:"ice_server_count,omitempty"`
}

type PluggableTransportPlan struct {
	Transport          string   `json:"transport"`
	Platform           string   `json:"platform"`
	ObservedState      string   `json:"observed_state"`
	Ready              bool     `json:"ready"`
	NextAction         string   `json:"next_action"`
	LocalPort          int      `json:"local_port"`
	ProxySupported     bool     `json:"proxy_supported"`
	NormalizedMaxPeers int      `json:"normalized_max_peers"`
	SingletonRequired  bool     `json:"singleton_required"`
	StateDirRequired   bool     `json:"state_dir_required"`
	SafeLogging        bool     `json:"safe_logging"`
	StartsTransport    bool     `json:"starts_transport"`
	PerformsNetworkIO  bool     `json:"performs_network_io"`
	WritesState        bool     `json:"writes_state"`
	Warnings           []string `json:"warnings"`
	Invariants         []string `json:"invariants"`
}

func BuildPluggableTransportPlan(req PluggableTransportPlanRequest) (PluggableTransportPlan, error) {
	transport := strings.ToLower(strings.TrimSpace(req.Transport))
	switch transport {
	case "obfs4", "meek", "snowflake", "webtunnel", "dnstt":
	default:
		return PluggableTransportPlan{}, fmt.Errorf("transport must be obfs4, meek, snowflake, webtunnel, or dnstt")
	}
	platform := strings.ToLower(strings.TrimSpace(req.Platform))
	switch platform {
	case "android", "ios", "macos", "windows", "linux":
	default:
		return PluggableTransportPlan{}, fmt.Errorf("platform must be android, ios, macos, windows, or linux")
	}
	state := strings.ToLower(strings.TrimSpace(req.ObservedState))
	if state == "" {
		state = "stopped"
	}
	switch state {
	case "stopped", "starting", "listening", "connected", "stopping", "error":
	default:
		return PluggableTransportPlan{}, fmt.Errorf("observed_state must be stopped, starting, listening, connected, stopping, or error")
	}
	proxyKind := strings.ToLower(strings.TrimSpace(req.OutboundProxyKind))
	if proxyKind == "" {
		proxyKind = "none"
	}
	switch proxyKind {
	case "none", "http", "socks4", "socks5":
	default:
		return PluggableTransportPlan{}, fmt.Errorf("outbound_proxy_kind must be none, http, socks4, or socks5")
	}
	proxySupported := transport != "snowflake" && transport != "dnstt"
	if !proxySupported && proxyKind != "none" {
		return PluggableTransportPlan{}, fmt.Errorf("%s does not support an outbound proxy in the admitted PT contract", transport)
	}
	if req.LocalPort < 0 || req.LocalPort > 65535 {
		return PluggableTransportPlan{}, fmt.Errorf("local_port must be 0..65535")
	}
	if (state == "listening" || state == "connected") && req.LocalPort == 0 {
		return PluggableTransportPlan{}, fmt.Errorf("%s state requires a discovered local listener port", state)
	}
	if req.FrontDomainCount < 0 || req.FrontDomainCount > maxPTFrontDomains {
		return PluggableTransportPlan{}, fmt.Errorf("front_domain_count must be 0..%d", maxPTFrontDomains)
	}
	if req.ICEServerCount < 0 || req.ICEServerCount > maxPTICEServers {
		return PluggableTransportPlan{}, fmt.Errorf("ice_server_count must be 0..%d", maxPTICEServers)
	}
	maxPeers := req.MaxPeers
	if transport == "snowflake" {
		if maxPeers == 0 {
			maxPeers = 1
		}
		if maxPeers < 1 || maxPeers > maxPTPeers {
			return PluggableTransportPlan{}, fmt.Errorf("snowflake max_peers must be 1..%d", maxPTPeers)
		}
	} else if maxPeers != 0 {
		return PluggableTransportPlan{}, fmt.Errorf("max_peers applies only to snowflake")
	}

	plan := PluggableTransportPlan{
		Transport: transport, Platform: platform, ObservedState: state, LocalPort: req.LocalPort,
		ProxySupported: proxySupported, NormalizedMaxPeers: maxPeers, SingletonRequired: true,
		StateDirRequired: true, SafeLogging: !req.UnsafeLogging, StartsTransport: false,
		PerformsNetworkIO: false, WritesState: false,
		Invariants: []string{
			"one controller owns a transport lifecycle; parallel controller instances are not admitted",
			"state storage must be explicitly configured and writable before a transport is considered start-ready",
			"local SOCKS listener identity is evidence only after a nonzero loopback port is reported",
			"Snowflake and DNSTT never silently inherit an outbound proxy that their admitted controller contract rejects",
			"unsafe address logging is never enabled implicitly",
			"the planner never creates state directories, listeners, PT processes, WebRTC sessions, or network connections",
		},
	}
	if req.UnsafeLogging {
		plan.Warnings = append(plan.Warnings, "unsafe logging disables address scrubbing and should remain an explicit diagnostic-only choice")
	}
	if req.LoggingEnabled && !req.StateDirConfigured {
		plan.Warnings = append(plan.Warnings, "logging was requested without an explicit state directory")
	}
	if !req.StateDirConfigured {
		plan.NextAction = "configure-state-dir"
	} else if !req.StateDirWritable {
		plan.NextAction = "repair-state-dir"
	} else {
		switch state {
		case "stopped", "error":
			plan.NextAction = "eligible-to-start"
		case "starting":
			plan.NextAction = "await-listener"
		case "listening", "connected":
			plan.NextAction = "hold"
		case "stopping":
			plan.NextAction = "await-stop"
		}
	}
	plan.Ready = req.StateDirConfigured && req.StateDirWritable && (state == "listening" || state == "connected") && req.LocalPort > 0
	return plan, nil
}
