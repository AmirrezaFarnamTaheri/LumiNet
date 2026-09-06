package routingplugin

import (
	"fmt"
	"strings"
)

type windscribePolicy struct{}

func (windscribePolicy) defaultDescriptor() RoutingPluginDescriptor {
	return RoutingPluginDescriptor{
		SchemaVersion:     1,
		PluginID:          "windscribe",
		PluginType:        "windscribe",
		DisplayName:       "Windscribe route adapter",
		Version:           "adapter-v1",
		SourceURL:         "https://windscribe.com/",
		License:           "external-provider-profile",
		RouteType:         "plugin",
		CredentialMode:    "user_supplied",
		LocalAPIMode:      "external_app",
		LocalAPIRequired:  false,
		SecretPolicy:      "credential_ref_only",
		Enabled:           true,
		EnabledByDefault:  false,
		SupportsIPv4:      true,
		SupportsIPv6:      true,
		SupportsRemoteDNS: true,
		DiagnosticLabel:   "Windscribe profile route",
		RedactedFields:    []string{"username", "password", "api_token", "session_auth_hash", "auth_hash", "secure_token", "captcha_solution", "wireguard_private_key", "openvpn_password"},
		Notes:             []string{"Edge-only adapter", "Absorb Windscribe as route capabilities: external VPN, local proxy gateway, OpenVPN UDP/TCP, Stealth, WSTunnel, WireGuard, IKEv2, DNS/ControlD/R.O.B.E.R.T policy, split tunnel policy, and wsnet-backed session references", "Windscribe public Android architecture routes API calls through wsnet; direct raw account API calls intentionally stay outside the Go sidecar boundary"},
	}
}

func (windscribePolicy) validateDescriptor(descriptor RoutingPluginDescriptor) error {
	if descriptor.SecretPolicy != "credential_ref_only" {
		return fmt.Errorf("%w: windscribe must use credential_ref_only secret policy", errPluginDescriptor)
	}
	return nil
}

func (windscribePolicy) extendAllowedFields(allowed map[string]bool) {
	for _, key := range []string{
		"route_strategy",
		"profile_type",
		"location_ref",
		"static_ip_ref",
		"port_forward_ref",
		"package_name",
		"session_ref",
		"api_profile_ref",
		"robert_policy_ref",
		"ctrld_profile_ref",
	} {
		allowed[key] = true
	}
}

func (windscribePolicy) validate(cfg RoutingPluginConfig) error {
	return validateWindscribeMode(cfg)
}

func (windscribePolicy) warnings(attachable bool) []string {
	warnings := []string{
		"windscribe adapter is Edge-only and expects user-owned external VPN/proxy/OpenVPN/WireGuard profile references",
		"Windscribe account login/session state remains Android-owned; Go receives only profile/session refs and route capabilities",
		"provider chaining such as psiphon_over_windscribe or windscribe_over_psiphon requires explicit upstream route refs",
	}
	if attachable {
		return append(warnings, "route attachment is enabled only when a validated local proxy endpoint is present; scan results must confirm observed route execution")
	}
	return append(warnings, "validated config remains readiness-only until a local proxy endpoint is attachable in scan execution")
}

func validateWindscribeMode(cfg RoutingPluginConfig) error {
	mode := strings.TrimSpace(strings.ToLower(cfg.Fields["mode"]))
	if mode == "" {
		mode = "external_vpn"
	}
	if !allowedValue(mode, "external_vpn", "local_proxy", "openvpn_udp", "openvpn_tcp", "tcp", "stealth", "wstunnel", "wireguard", "ikev2") {
		return fmt.Errorf("%w: unsupported windscribe mode %q", errPluginConfig, mode)
	}
	authMode := normalizedField(cfg, "auth_mode", "none")
	if !allowedValue(authMode, "none", "external_app", "profile_ref", "credential_ref", "auth_token_ref", "sso_external", "wsnet_session_ref", "wsnet_login_required") {
		return fmt.Errorf("%w: unsupported windscribe auth_mode %q", errPluginConfig, cfg.Fields["auth_mode"])
	}
	if authMode == "wsnet_login_required" {
		return fmt.Errorf("%w: windscribe wsnet login flow belongs to Android session ownership; use external_app/profile_ref/credential_ref/auth_token_ref/sso_external/wsnet_session_ref", errPluginConfig)
	}
	if authMode == "wsnet_session_ref" && strings.TrimSpace(cfg.CredentialRef) == "" {
		return fmt.Errorf("%w: windscribe wsnet_session_ref requires credential_ref containing a stored session handle", errPluginConfig)
	}
	if allowedValue(authMode, "auth_token_ref", "sso_external") && strings.TrimSpace(cfg.CredentialRef) == "" {
		return fmt.Errorf("%w: windscribe %s requires credential_ref", errPluginConfig, authMode)
	}
	if mode == "local_proxy" {
		if err := validateProxyEndpoint(cfg.Endpoint); err != nil {
			return err
		}
	}
	if allowedValue(mode, "openvpn_udp", "openvpn_tcp", "stealth", "wstunnel", "wireguard") && strings.TrimSpace(cfg.ProfileRef) == "" {
		return fmt.Errorf("%w: windscribe protocol mode requires profile_ref", errPluginConfig)
	}
	if allowedValue(mode, "tcp", "ikev2") && strings.TrimSpace(cfg.ProfileRef) == "" {
		return fmt.Errorf("%w: windscribe protocol mode requires profile_ref", errPluginConfig)
	}
	if strategy := normalizedRouteStrategy(RoutingPluginDescriptor{PluginType: "windscribe"}, cfg); !allowedValue(strategy, "provider_default", "direct", "profile_default") {
		return fmt.Errorf("%w: unsupported windscribe route_strategy %q", errPluginConfig, strategy)
	}
	return validateRoutePolicyFields(cfg)
}

func (windscribePolicy) describe(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) routingPluginPolicyDescription {
	mode := normalizedProtocolMode(plugin, cfg)
	readinessProbe := "verify external VPN/profile route via user-selected profile reference and route observation"
	if mode == "local_proxy" {
		readinessProbe = "probe user-supplied Windscribe-routed local SOCKS/HTTP proxy endpoint"
	} else if normalizedAuthMode(plugin, cfg) == "wsnet_session_ref" {
		readinessProbe = "validate stored wsnet session handle, fetch session/server/profile metadata through wsnet adapter, then verify route observation"
	}

	components := []string{"edge_route_manager", "route_observer", "redaction_filter"}
	switch mode {
	case "local_proxy":
		components = append(components, "local_proxy_probe", "proxy_gateway_policy")
	case "openvpn_udp", "openvpn_tcp":
		components = append(components, "openvpn_profile_ref", "protocol_profile_validator")
	case "stealth":
		components = append(components, "openvpn_tcp_profile_ref", "stunnel_profile_metadata")
	case "wstunnel":
		components = append(components, "openvpn_profile_ref", "websocket_tunnel_profile_metadata")
	case "wireguard":
		components = append(components, "wireguard_profile_ref", "wireguard_secret_guard")
	case "ikev2":
		components = append(components, "ikev2_profile_ref", "platform_vpn_capability_check")
	default:
		components = append(components, "external_vpn_observer")
	}
	if normalizedAuthMode(plugin, cfg) == "wsnet_session_ref" {
		components = append(components, "wsnet_session_ref_adapter")
	}
	switch normalizedField(cfg, "dns_policy", "system_or_route_default") {
	case "ctrld", "control_d":
		components = append(components, "ctrld_dns_policy")
	case "robert":
		components = append(components, "robert_filter_policy")
	case "doh", "dot", "custom_dns_ref":
		components = append(components, "custom_dns_policy")
	}
	if normalizedField(cfg, "split_tunnel", "scanner_app_only") != "scanner_app_only" {
		components = append(components, "split_tunnel_policy")
	}
	if normalizedProviderChain(cfg) != "none" {
		components = append(components, "provider_chain_supervisor")
	}
	if lanSharingEnabled(cfg) {
		components = append(components, "lan_proxy_gateway_policy")
	}

	return routingPluginPolicyDescription{
		ReadinessProbe: readinessProbe,
		Capabilities: []string{
			"external_vpn_route_labeling",
			"local_proxy_gateway",
			"openvpn_udp",
			"openvpn_tcp",
			"tcp_mode_alias",
			"stealth_stunnel",
			"wstunnel",
			"wireguard",
			"ikev2_external_profile",
			"dns_policy",
			"ctrld_policy",
			"robert_dns_filter_policy",
			"split_tunnel_policy",
			"upstream_downstream_route_observation",
			"provider_route_chaining",
			"lan_proxy_gateway_metadata",
			"custom_openvpn_wireguard_profile_refs",
			"optional_auth_token_or_sso_reference",
			"optional_wsnet_session_ref_auth_boundary",
			"interactive_login_flow_planned_not_raw_http",
		},
		Components: components,
		Observations: append(baseRouteObservations(),
			"protocol_mode", "auth_mode", "split_tunnel", "upstream_mode", "downstream_mode", "proxy_gateway_scope",
			"provider_chain", "lan_sharing", "external_ip_delta", "dns_resolver_delta"),
		Evidence: map[string]any{
			"upstream_downstream_model":   true,
			"dns_resolver_delta_required": normalizedField(cfg, "dns_policy", "system_or_route_default") != "no_dns",
		},
	}
}
