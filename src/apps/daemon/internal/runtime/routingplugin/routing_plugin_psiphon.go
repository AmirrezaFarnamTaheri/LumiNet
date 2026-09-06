package routingplugin

import (
	"fmt"
	"strconv"
	"strings"
)

type psiphonPolicy struct{}

func (psiphonPolicy) defaultDescriptor() RoutingPluginDescriptor {
	return RoutingPluginDescriptor{
		SchemaVersion:     1,
		PluginID:          "psiphon",
		PluginType:        "psiphon",
		DisplayName:       "Psiphon route adapter",
		Version:           "adapter-v1",
		SourceURL:         "local://psiphon-adapter",
		License:           "GPL-3.0-family",
		RouteType:         "plugin",
		CredentialMode:    "imported_config_ref",
		LocalAPIMode:      "none",
		LocalAPIRequired:  false,
		SecretPolicy:      "imported_config_ref",
		Enabled:           true,
		EnabledByDefault:  false,
		SupportsIPv4:      true,
		SupportsIPv6:      false,
		SupportsRemoteDNS: true,
		DiagnosticLabel:   "Psiphon plugin route",
		RedactedFields:    []string{"client_secret", "client_config", "authorization", "proxy_password"},
		Notes:             []string{"Edge-only adapter", "Matches Se7en-Pro style tunnel-core supervision: imported config, local SOCKS/HTTP proxy readiness, process diagnostics", "No embedded provider secret"},
	}
}

func (psiphonPolicy) validateDescriptor(descriptor RoutingPluginDescriptor) error {
	if descriptor.SecretPolicy != "imported_config_ref" {
		return fmt.Errorf("%w: psiphon must use imported_config_ref secret policy", errPluginDescriptor)
	}
	return nil
}

func (psiphonPolicy) extendAllowedFields(allowed map[string]bool) {
	for _, key := range []string{
		"package_name",
		"route_strategy",
		"protocol_selection",
		"conduit_mode",
		"conduit_timeout_seconds",
		"reject_censored_country_proxies",
		"conduit_fallback_to_public",
		"fronting_ip_ref",
		"cdn_fronting_ip_ref",
		"fronting_sni",
		"cdn_fronting_sni",
		"beast_mode",
		"establishment_intensity",
		"sponsor_id_ref",
		"device_location_ref",
		"client_secret",
		"region",
	} {
		allowed[key] = true
	}
}

func (psiphonPolicy) validate(cfg RoutingPluginConfig) error {
	return validatePsiphonMode(cfg)
}

func (psiphonPolicy) warnings(attachable bool) []string {
	warnings := []string{
		"psiphon adapter is Edge-only; standard mode is tunnel-core/library supervision with operator-supplied config reference",
		"external Psiphon APK/VPN mode can only label and test a user-connected route unless a documented control API exists",
		"conduit/CDN-fronting/beast-mode fields are route establishment policy inputs and must be verified by notices, proxy readiness, and scan attribution",
	}
	if attachable {
		return append(warnings, "route attachment is enabled only when a validated local proxy endpoint is present; scan results must confirm observed route execution")
	}
	return append(warnings, "validated config remains readiness-only until a local proxy endpoint is attachable in scan execution")
}

func validatePsiphonMode(cfg RoutingPluginConfig) error {
	mode := strings.TrimSpace(strings.ToLower(cfg.Fields["mode"]))
	if mode == "" {
		mode = "tunnel_core_supervised"
	}
	if !allowedValue(mode, "tunnel_core_supervised", "tunnel_core_library", "external_vpn_apk", "external_vpn") {
		return fmt.Errorf("%w: unsupported psiphon mode %q", errPluginConfig, mode)
	}
	switch mode {
	case "tunnel_core_supervised", "tunnel_core_library":
		if strings.TrimSpace(cfg.ConfigRef) == "" {
			return fmt.Errorf("%w: psiphon tunnel-core mode requires config_ref, not inline ClientSecret/config data", errPluginConfig)
		}
		if strings.TrimSpace(cfg.Endpoint) != "" {
			if err := validateProxyEndpoint(cfg.Endpoint); err != nil {
				return err
			}
		}
		if strings.TrimSpace(cfg.LocalAPIURL) != "" {
			if _, err := parseLocalPluginAPI(cfg.LocalAPIURL); err != nil {
				return err
			}
		}
	case "external_vpn_apk", "external_vpn":
		if strings.TrimSpace(cfg.ProfileRef) == "" && strings.TrimSpace(cfg.Fields["package_name"]) == "" {
			return fmt.Errorf("%w: psiphon external APK/VPN mode requires profile_ref or package_name", errPluginConfig)
		}
	}
	if err := validatePsiphonRouteStrategy(cfg); err != nil {
		return err
	}
	return validateRoutePolicyFields(cfg)
}

func validatePsiphonRouteStrategy(cfg RoutingPluginConfig) error {
	strategy := normalizedRouteStrategy(RoutingPluginDescriptor{PluginType: "psiphon"}, cfg)
	if !allowedValue(strategy, "auto", "conduit_first", "conduit", "cdn_fronting", "direct") {
		return fmt.Errorf("%w: unsupported psiphon route_strategy %q", errPluginConfig, strategy)
	}
	if !allowedValue(normalizedConduitMode(cfg), "", "auto", "shirokhorshid", "public") {
		return fmt.Errorf("%w: unsupported psiphon conduit_mode %q", errPluginConfig, cfg.Fields["conduit_mode"])
	}
	if timeoutValue := strings.TrimSpace(cfg.Fields["conduit_timeout_seconds"]); timeoutValue != "" {
		timeoutSeconds, err := strconv.Atoi(timeoutValue)
		if err != nil || timeoutSeconds < 15 || timeoutSeconds > 1800 {
			return fmt.Errorf("%w: conduit_timeout_seconds must be between 15 and 1800", errPluginConfig)
		}
	}
	for _, key := range []string{"reject_censored_country_proxies", "conduit_fallback_to_public", "beast_mode", "share_proxy_on_lan"} {
		if value := strings.TrimSpace(cfg.Fields[key]); value != "" && !isBoolText(value) {
			return fmt.Errorf("%w: %s must be true or false", errPluginConfig, key)
		}
	}
	if strategy == "cdn_fronting" || normalizedFrontingPolicy(cfg) != "" {
		if strings.TrimSpace(cfg.Fields["fronting_ip_ref"]) == "" && strings.TrimSpace(cfg.Fields["cdn_fronting_ip_ref"]) == "" && strings.TrimSpace(cfg.Fields["fronting_sni"]) == "" && strings.TrimSpace(cfg.Fields["cdn_fronting_sni"]) == "" {
			return fmt.Errorf("%w: cdn_fronting route strategy requires a fronting_ip_ref or fronting_sni/cdn_fronting_sni", errPluginConfig)
		}
	}
	for _, key := range []string{"fronting_sni", "cdn_fronting_sni"} {
		if value := strings.TrimSpace(cfg.Fields[key]); value != "" && !isSafeHostnameLike(value) {
			return fmt.Errorf("%w: %s must be a hostname-like value", errPluginConfig, key)
		}
	}
	return nil
}

func (psiphonPolicy) describe(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) routingPluginPolicyDescription {
	mode := normalizedProtocolMode(plugin, cfg)
	readinessProbe := "check tunnel-core/library state, parse diagnostic notices such as ListeningSocksProxyPort/ListeningHttpProxyPort, and probe local SOCKS/HTTP proxy on loopback"
	if mode == "external_vpn_apk" || mode == "external_vpn" {
		readinessProbe = "verify user-connected Psiphon APK/VPN route by external IP, DNS path, and route observation; do not drive private APK UI"
	}

	capabilities := []string{
		"tunnel_core_supervision",
		"external_vpn_apk_labeling",
		"local_socks_http_proxy_readiness",
		"diagnostic_notice_parsing",
		"conduit_route_strategy",
		"cdn_fronting_route_strategy",
		"beast_establishment_intensity",
		"conduit_public_fallback_policy",
		"lan_proxy_sharing_policy",
		"upstream_proxy_policy",
		"remote_dns_when_route_attached",
	}
	if normalizedProviderChain(cfg) != "none" {
		capabilities = append(capabilities, "provider_route_chaining")
	}

	components := []string{"psiphon_tunnel_core", "config_ref_store", "process_supervisor", "diagnostic_notice_parser", "local_proxy_probe", "route_manager"}
	if mode == "external_vpn_apk" || mode == "external_vpn" {
		components = []string{"external_psiphon_app", "android_vpn_observer", "route_observer"}
	} else {
		switch normalizedRouteStrategy(plugin, cfg) {
		case "conduit", "conduit_first":
			components = append(components, "conduit_selector", "conduit_fallback_timer")
		case "cdn_fronting":
			components = append(components, "cdn_fronting_policy")
		}
		if beastModeEnabled(cfg) {
			components = append(components, "aggressive_establishment_policy")
		}
		if lanSharingEnabled(cfg) {
			components = append(components, "lan_proxy_gateway_policy")
		}
		if normalizedProviderChain(cfg) != "none" {
			components = append(components, "provider_chain_supervisor")
		}
	}

	description := routingPluginPolicyDescription{
		ReadinessProbe: readinessProbe,
		Capabilities:   capabilities,
		Components:     components,
		Observations: append(baseRouteObservations(),
			"route_strategy", "conduit_mode", "fronting_policy", "beast_mode", "provider_chain", "lan_sharing",
			"tunnel_core_pid", "listening_socks_port", "listening_http_proxy_port", "diagnostic_notice_state", "external_ip_delta"),
	}
	if mode == "tunnel_core_supervised" || mode == "tunnel_core_library" {
		description.Evidence = map[string]any{
			"required_readiness_state":   "proxy_listening",
			"required_notice_fields":     []string{"ListeningSocksProxyPort", "ListeningHttpProxyPort"},
			"shirokhorshid_config_model": []string{"protocolSelection", "cdnFrontingCustomIpList", "cdnFrontingCustomSni", "beastMode", "conduitMode", "shareProxyOnNetwork"},
		}
	}
	return description
}
