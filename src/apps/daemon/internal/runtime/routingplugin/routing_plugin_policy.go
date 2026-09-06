package routingplugin

import (
	"fmt"
	"strings"
)

type routingPluginPolicy interface {
	defaultDescriptor() RoutingPluginDescriptor
	validateDescriptor(RoutingPluginDescriptor) error
	extendAllowedFields(map[string]bool)
	validate(RoutingPluginConfig) error
	warnings(attachable bool) []string
	describe(RoutingPluginDescriptor, RoutingPluginConfig) routingPluginPolicyDescription
}

type routingPluginPolicyDescription struct {
	ReadinessProbe string
	Capabilities   []string
	Components     []string
	Observations   []string
	Evidence       map[string]any
}

func routingPluginPolicies() []routingPluginPolicy {
	return []routingPluginPolicy{genericProxyPolicy{}, psiphonPolicy{}, windscribePolicy{}}
}

func defaultRoutingPluginDescriptors() []RoutingPluginDescriptor {
	policies := routingPluginPolicies()
	descriptors := make([]RoutingPluginDescriptor, 0, len(policies))
	for _, policy := range policies {
		descriptors = append(descriptors, policy.defaultDescriptor())
	}
	return descriptors
}

func routingPluginPolicyForType(pluginType string) (routingPluginPolicy, bool) {
	for _, policy := range routingPluginPolicies() {
		if policy.defaultDescriptor().PluginType == pluginType {
			return policy, true
		}
	}
	return nil, false
}

func routingPluginPolicyFor(plugin RoutingPluginDescriptor) (routingPluginPolicy, error) {
	policy, ok := routingPluginPolicyForType(plugin.PluginType)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported plugin type %q", errPluginConfig, plugin.PluginType)
	}
	return policy, nil
}

func validateProviderFieldAllowlist(policy routingPluginPolicy, plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) error {
	allowed := map[string]bool{
		"mode":                 true,
		"auth_mode":            true,
		"dns_policy":           true,
		"dns_ref":              true,
		"split_tunnel":         true,
		"upstream_mode":        true,
		"upstream_proxy_ref":   true,
		"downstream_mode":      true,
		"proxy_gateway_scope":  true,
		"gateway_auth_ref":     true,
		"local_socks_port":     true,
		"local_http_port":      true,
		"lan_socks_port":       true,
		"lan_http_port":        true,
		"share_proxy_on_lan":   true,
		"route_strategy":       true,
		"provider_chain":       true,
		"chain_upstream_ref":   true,
		"chain_downstream_ref": true,
	}
	policy.extendAllowedFields(allowed)
	for key := range cfg.Fields {
		if !allowed[strings.ToLower(key)] {
			return fmt.Errorf("%w: provider field %q is not supported for %s", errPluginConfig, key, plugin.PluginID)
		}
	}
	return nil
}

type genericProxyPolicy struct{}

func (genericProxyPolicy) defaultDescriptor() RoutingPluginDescriptor {
	return RoutingPluginDescriptor{
		SchemaVersion:     1,
		PluginID:          "generic-proxy",
		PluginType:        "generic_proxy",
		DisplayName:       "Generic proxy route",
		Version:           "adapter-v1",
		SourceURL:         "local://generic-proxy",
		License:           "app-native",
		RouteType:         "socks5",
		CredentialMode:    "user_supplied",
		LocalAPIMode:      "none",
		LocalAPIRequired:  false,
		SecretPolicy:      "credential_ref_only",
		Enabled:           true,
		EnabledByDefault:  true,
		SupportsIPv4:      true,
		SupportsIPv6:      true,
		SupportsRemoteDNS: true,
		DiagnosticLabel:   "Generic SOCKS/HTTP proxy",
		RedactedFields:    []string{"username", "password", "proxy_authorization"},
		Notes:             []string{"Credentials are references only and must not be logged"},
	}
}

func (genericProxyPolicy) validateDescriptor(RoutingPluginDescriptor) error { return nil }

func (genericProxyPolicy) extendAllowedFields(map[string]bool) {}

func (genericProxyPolicy) validate(cfg RoutingPluginConfig) error {
	return validateProxyEndpoint(cfg.Endpoint)
}

func (genericProxyPolicy) warnings(bool) []string { return nil }

func (genericProxyPolicy) describe(RoutingPluginDescriptor, RoutingPluginConfig) routingPluginPolicyDescription {
	return routingPluginPolicyDescription{
		ReadinessProbe: "probe configured SOCKS/HTTP proxy endpoint before attaching route",
		Capabilities:   []string{"socks5", "http_connect", "remote_dns_when_route_attached", "credential_ref_only"},
		Components:     []string{"generic_proxy_parser", "local_proxy_probe", "route_manager"},
		Observations:   append(baseRouteObservations(), "proxy_protocol", "proxy_connect_status"),
	}
}

func baseRouteObservations() []string {
	return []string{"route_id", "route_binding", "network_path", "dns_policy", "remote_dns", "readiness_probe", "latency_ms", "last_error_code"}
}
