package routingplugin

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

var errPluginDescriptor = errors.New("invalid routing plugin descriptor")
var errRouteValidation = errors.New("route configuration is invalid")

var ErrPluginConfig = errPluginConfig
var ErrPluginDescriptor = errPluginDescriptor
var ErrRouteValidation = errRouteValidation

type RoutingPluginRegistry struct {
	descriptors map[string]RoutingPluginDescriptor
}

func DefaultRoutingPluginRegistry() (*RoutingPluginRegistry, error) {
	return NewRoutingPluginRegistry(defaultRoutingPluginDescriptors())
}

func NewRoutingPluginRegistry(descriptors []RoutingPluginDescriptor) (*RoutingPluginRegistry, error) {
	reg := &RoutingPluginRegistry{descriptors: map[string]RoutingPluginDescriptor{}}
	for _, descriptor := range descriptors {
		if err := validateRoutingPluginDescriptor(descriptor); err != nil {
			return nil, err
		}
		if _, exists := reg.descriptors[descriptor.PluginID]; exists {
			return nil, fmt.Errorf("%w: duplicate plugin_id %q", errPluginDescriptor, descriptor.PluginID)
		}
		reg.descriptors[descriptor.PluginID] = descriptor
	}
	return reg, nil
}

func validateRoutingPluginDescriptor(d RoutingPluginDescriptor) error {
	if d.SchemaVersion != 1 {
		return fmt.Errorf("%w: unsupported schema_version %d", errPluginDescriptor, d.SchemaVersion)
	}
	required := []string{d.PluginID, d.PluginType, d.DisplayName, d.Version, d.SourceURL, d.License, d.RouteType, d.CredentialMode, d.LocalAPIMode, d.SecretPolicy, d.DiagnosticLabel}
	if containsCRLF(required...) {
		return fmt.Errorf("%w: descriptor strings must not contain CR/LF", errPluginDescriptor)
	}
	for _, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: required descriptor field is empty", errPluginDescriptor)
		}
	}
	if d.EnabledByDefault && !d.Enabled {
		return fmt.Errorf("%w: enabled_by_default requires enabled", errPluginDescriptor)
	}
	policy, ok := routingPluginPolicyForType(d.PluginType)
	if !ok {
		return fmt.Errorf("%w: unsupported plugin_type %q", errPluginDescriptor, d.PluginType)
	}
	if !allowedValue(d.RouteType, "socks5", "http_connect", "plugin", "vpn") {
		return fmt.Errorf("%w: unsupported route_type %q", errPluginDescriptor, d.RouteType)
	}
	if !allowedValue(d.CredentialMode, "none", "user_supplied", "credential_ref_only", "imported_config_ref", "external_app") {
		return fmt.Errorf("%w: unsupported credential_mode %q", errPluginDescriptor, d.CredentialMode)
	}
	if !allowedValue(d.LocalAPIMode, "none", "authenticated_http", "authenticated_unix_socket", "external_app") {
		return fmt.Errorf("%w: unsupported local_api_mode %q", errPluginDescriptor, d.LocalAPIMode)
	}
	if !allowedValue(d.SecretPolicy, "none", "credential_ref_only", "imported_config_ref", "external_app") {
		return fmt.Errorf("%w: unsupported secret_policy %q", errPluginDescriptor, d.SecretPolicy)
	}
	if d.LocalAPIRequired && d.LocalAPIMode == "none" {
		return fmt.Errorf("%w: local_api_required cannot use local_api_mode=none", errPluginDescriptor)
	}
	return policy.validateDescriptor(d)
}

func (r *RoutingPluginRegistry) List() []RoutingPluginDescriptor {
	out := make([]RoutingPluginDescriptor, 0, len(r.descriptors))
	for _, descriptor := range r.descriptors {
		out = append(out, descriptor)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PluginID < out[j].PluginID })
	return out
}

func (r *RoutingPluginRegistry) Get(pluginID string) (RoutingPluginDescriptor, bool) {
	descriptor, ok := r.descriptors[pluginID]
	return descriptor, ok
}

func redactPluginDiagnostics(plugin RoutingPluginDescriptor, fields map[string]string) map[string]string {
	redacted := make(map[string]string, len(fields))
	secretNames := map[string]bool{}
	for _, field := range plugin.RedactedFields {
		secretNames[strings.ToLower(field)] = true
	}
	for key, value := range fields {
		lower := strings.ToLower(key)
		if secretNames[lower] || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "authorization") || strings.Contains(lower, "private_key") {
			redacted[key] = "[REDACTED]"
		} else {
			redacted[key] = value
		}
	}
	return redacted
}

func ValidateRoutingPluginConfig(registry *RoutingPluginRegistry, cfg RoutingPluginConfig) (RoutingPluginConfigValidation, error) {
	if cfg.SchemaVersion != 1 {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: unsupported schema_version %d", errPluginConfig, cfg.SchemaVersion)
	}
	if containsCRLF(cfg.RouteID, cfg.PluginID, cfg.Endpoint, cfg.LocalAPIURL, cfg.CredentialRef, cfg.ConfigRef, cfg.ProfileRef) {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: config strings must not contain CR/LF", errPluginConfig)
	}
	if err := validatePluginFieldMap(cfg.Fields); err != nil {
		return RoutingPluginConfigValidation{}, err
	}
	if strings.TrimSpace(cfg.RouteID) == "" || strings.TrimSpace(cfg.PluginID) == "" {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: route_id and plugin_id are required", errPluginConfig)
	}
	plugin, ok := registry.Get(cfg.PluginID)
	if !ok {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: unknown plugin_id %q", errPluginConfig, cfg.PluginID)
	}
	if !plugin.Enabled {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: plugin %q is not available in this build", errPluginConfig, cfg.PluginID)
	}
	policy, err := routingPluginPolicyFor(plugin)
	if err != nil {
		return RoutingPluginConfigValidation{}, err
	}
	if err := validateProviderFieldAllowlist(policy, plugin, cfg); err != nil {
		return RoutingPluginConfigValidation{}, err
	}
	if cfg.RemoteDNS && !plugin.SupportsRemoteDNS {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: plugin %q does not support remote DNS", errPluginConfig, cfg.PluginID)
	}
	if err := policy.validate(cfg); err != nil {
		return RoutingPluginConfigValidation{}, err
	}
	if plugin.LocalAPIRequired && !isLocalPluginAPI(cfg.LocalAPIURL) {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: plugin %q requires localhost local_api_url", errPluginConfig, cfg.PluginID)
	}
	if leaksInlineSecret(plugin, cfg) {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: inline secret detected; use credential_ref/config_ref/profile_ref", errPluginConfig)
	}
	redacted := map[string]string{
		"route_id":       cfg.RouteID,
		"plugin_id":      cfg.PluginID,
		"endpoint":       cfg.Endpoint,
		"local_api_url":  cfg.LocalAPIURL,
		"credential_ref": cfg.CredentialRef,
		"config_ref":     cfg.ConfigRef,
		"profile_ref":    cfg.ProfileRef,
	}
	for key, value := range cfg.Fields {
		redacted[key] = value
	}
	redacted = redactPluginDiagnostics(plugin, redacted)
	routeBinding := routeBindingForPlugin(plugin, cfg)
	protocolMode := normalizedProtocolMode(plugin, cfg)
	attachable := routeAttachable(plugin, cfg, routeBinding, protocolMode)
	warnings := policy.warnings(attachable)
	description := policy.describe(plugin, cfg)
	observation := routeObservationPreview(plugin, cfg, description)
	if err := validateRouteObservationTemplate(observation); err != nil {
		return RoutingPluginConfigValidation{}, err
	}
	return RoutingPluginConfigValidation{
		Valid:          true,
		RouteID:        cfg.RouteID,
		PluginID:       cfg.PluginID,
		PluginType:     plugin.PluginType,
		RouteType:      plugin.RouteType,
		RemoteDNS:      cfg.RemoteDNS,
		AuthMode:       normalizedAuthMode(plugin, cfg),
		ProtocolMode:   protocolMode,
		DNSPolicy:      normalizedField(cfg, "dns_policy", "system_or_route_default"),
		SplitTunnel:    normalizedField(cfg, "split_tunnel", "scanner_app_only"),
		UpstreamMode:   normalizedField(cfg, "upstream_mode", "none"),
		DownstreamMode: normalizedField(cfg, "downstream_mode", "scanner_to_route"),
		RouteBinding:   routeBinding,
		RouteStrategy:  normalizedRouteStrategy(plugin, cfg),
		ConduitMode:    normalizedConduitMode(cfg),
		ProviderChain:  normalizedProviderChain(cfg),
		FrontingPolicy: normalizedFrontingPolicy(cfg),
		LANSharing:     lanSharingEnabled(cfg),
		BeastMode:      beastModeEnabled(cfg),
		DryRunOnly:     true,
		Attachable:     attachable,
		ReadinessProbe: description.ReadinessProbe,
		Capabilities:   description.Capabilities,
		Components:     description.Components,
		Observations:   description.Observations,
		Observation:    observation,
		RedactedConfig: redacted,
		Warnings:       warnings,
		Descriptor:     plugin,
	}, nil
}

func validatePluginFieldMap(fields map[string]string) error {
	const maxPluginFields = 64
	const maxPluginFieldKeyBytes = 96
	const maxPluginFieldValueBytes = 4096
	if len(fields) > maxPluginFields {
		return fmt.Errorf("%w: too many provider fields", errPluginConfig)
	}
	for key, value := range fields {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			return fmt.Errorf("%w: provider field key is required", errPluginConfig)
		}
		if key != trimmedKey {
			return fmt.Errorf("%w: provider field keys must not have surrounding whitespace", errPluginConfig)
		}
		if key != strings.ToLower(key) {
			return fmt.Errorf("%w: provider field keys must be lowercase", errPluginConfig)
		}
		if len(key) > maxPluginFieldKeyBytes {
			return fmt.Errorf("%w: provider field key is too long", errPluginConfig)
		}
		if len(value) > maxPluginFieldValueBytes {
			return fmt.Errorf("%w: provider field value for %q is too long", errPluginConfig, key)
		}
		if containsCRLF(key, value) {
			return fmt.Errorf("%w: provider fields must not contain CR/LF", errPluginConfig)
		}
		if strings.ContainsAny(key, "\x00\t ") || !isPluginFieldKey(key) {
			return fmt.Errorf("%w: provider field key %q is invalid", errPluginConfig, key)
		}
	}
	return nil
}

func isPluginFieldKey(key string) bool {
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func leaksInlineSecret(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) bool {
	fields := map[string]string{}
	for key, value := range cfg.Fields {
		fields[key] = value
	}
	fields["credential_ref"] = cfg.CredentialRef
	fields["config_ref"] = cfg.ConfigRef
	fields["profile_ref"] = cfg.ProfileRef
	fields["endpoint"] = cfg.Endpoint
	for key, value := range fields {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "ref") {
			continue
		}
		if value == "" {
			continue
		}
		if isSecretField(plugin, lower) && !strings.HasPrefix(value, "ref:") {
			return true
		}
	}
	return false
}

func isSecretField(plugin RoutingPluginDescriptor, lower string) bool {
	for _, field := range plugin.RedactedFields {
		if strings.ToLower(field) == lower {
			return true
		}
	}
	return strings.Contains(lower, "secret") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "authorization") ||
		strings.Contains(lower, "private_key")
}

func isLocalPluginAPI(value string) bool {
	_, err := parseLocalPluginAPI(value)
	return err == nil
}

func parseLocalPluginAPI(value string) (*url.URL, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("%w: local_api_url is required", errPluginConfig)
	}
	if containsCRLF(value) {
		return nil, fmt.Errorf("%w: local_api_url must not contain CR/LF", errPluginConfig)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid local_api_url: %v", errPluginConfig, err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: local_api_url must not contain credentials, query, or fragment", errPluginConfig)
	}
	switch parsed.Scheme {
	case "http":
		host := parsed.Hostname()
		port := parsed.Port()
		if !isLoopbackHost(host) || !validPort(port) {
			return nil, fmt.Errorf("%w: local_api_url must use loopback host and numeric port", errPluginConfig)
		}
	case "unix":
		if strings.TrimSpace(parsed.Path) == "" {
			return nil, fmt.Errorf("%w: unix local_api_url requires an app-private socket path", errPluginConfig)
		}
	default:
		return nil, fmt.Errorf("%w: local_api_url scheme must be http or unix", errPluginConfig)
	}
	return parsed, nil
}

func validateRoutePolicyFields(cfg RoutingPluginConfig) error {
	if !allowedValue(normalizedField(cfg, "dns_policy", "system_or_route_default"),
		"system_or_route_default", "remote_dns", "route_dns", "ctrld", "control_d", "robert", "doh", "dot", "custom_dns_ref", "no_dns") {
		return fmt.Errorf("%w: unsupported dns_policy %q", errPluginConfig, cfg.Fields["dns_policy"])
	}
	if !allowedValue(normalizedField(cfg, "split_tunnel", "scanner_app_only"),
		"scanner_app_only", "include_targets", "exclude_targets", "external_vpn_policy", "disabled") {
		return fmt.Errorf("%w: unsupported split_tunnel %q", errPluginConfig, cfg.Fields["split_tunnel"])
	}
	if !allowedValue(normalizedField(cfg, "upstream_mode", "none"),
		"none", "system_proxy", "proxy_ref", "direct", "provider_default") {
		return fmt.Errorf("%w: unsupported upstream_mode %q", errPluginConfig, cfg.Fields["upstream_mode"])
	}
	if !allowedValue(normalizedField(cfg, "downstream_mode", "scanner_to_route"),
		"scanner_to_route", "local_proxy_gateway", "vpn_interface", "provider_default") {
		return fmt.Errorf("%w: unsupported downstream_mode %q", errPluginConfig, cfg.Fields["downstream_mode"])
	}
	if !allowedValue(normalizedField(cfg, "proxy_gateway_scope", "loopback_only"),
		"loopback_only", "lan_shared") {
		return fmt.Errorf("%w: unsupported proxy_gateway_scope %q", errPluginConfig, cfg.Fields["proxy_gateway_scope"])
	}
	if normalizedField(cfg, "split_tunnel", "scanner_app_only") != "scanner_app_only" && strings.TrimSpace(cfg.ProfileRef) == "" {
		return fmt.Errorf("%w: split_tunnel policy requires profile_ref", errPluginConfig)
	}
	if normalizedField(cfg, "dns_policy", "system_or_route_default") == "custom_dns_ref" && strings.TrimSpace(cfg.Fields["dns_ref"]) == "" {
		return fmt.Errorf("%w: custom_dns_ref dns_policy requires dns_ref", errPluginConfig)
	}
	if normalizedField(cfg, "upstream_mode", "none") == "proxy_ref" && strings.TrimSpace(cfg.Fields["upstream_proxy_ref"]) == "" {
		return fmt.Errorf("%w: upstream proxy_ref requires upstream_proxy_ref", errPluginConfig)
	}
	if normalizedField(cfg, "proxy_gateway_scope", "loopback_only") == "lan_shared" && strings.TrimSpace(cfg.Fields["gateway_auth_ref"]) == "" {
		return fmt.Errorf("%w: lan_shared proxy gateway requires gateway_auth_ref", errPluginConfig)
	}
	if lanSharingEnabled(cfg) && normalizedField(cfg, "proxy_gateway_scope", "loopback_only") != "lan_shared" {
		return fmt.Errorf("%w: share_proxy_on_lan requires proxy_gateway_scope=lan_shared", errPluginConfig)
	}
	for _, key := range []string{"local_socks_port", "local_http_port", "lan_socks_port", "lan_http_port"} {
		if value := strings.TrimSpace(cfg.Fields[key]); value != "" && !validPort(value) {
			return fmt.Errorf("%w: %s must be a numeric TCP port", errPluginConfig, key)
		}
	}
	chain := normalizedProviderChain(cfg)
	if !allowedValue(chain, "none", "psiphon_over_windscribe", "windscribe_over_psiphon", "generic_proxy_over_windscribe", "windscribe_over_generic_proxy") {
		return fmt.Errorf("%w: unsupported provider_chain %q", errPluginConfig, cfg.Fields["provider_chain"])
	}
	if chain != "none" && strings.TrimSpace(cfg.Fields["chain_upstream_ref"]) == "" {
		return fmt.Errorf("%w: provider_chain requires chain_upstream_ref", errPluginConfig)
	}
	return nil
}

func routeObservationPreview(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig, description routingPluginPolicyDescription) RouteObservationPreview {
	providerID := plugin.PluginType
	if plugin.PluginType == "generic_proxy" {
		providerID = ""
	}
	routeBinding := routeBindingForPlugin(plugin, cfg)
	protocolMode := normalizedProtocolMode(plugin, cfg)
	authMode := normalizedAuthMode(plugin, cfg)
	dnsPolicy := normalizedField(cfg, "dns_policy", "system_or_route_default")
	splitTunnel := normalizedField(cfg, "split_tunnel", "scanner_app_only")
	upstreamMode := normalizedField(cfg, "upstream_mode", "none")
	downstreamMode := normalizedField(cfg, "downstream_mode", "scanner_to_route")
	proxyGatewayMode := normalizedField(cfg, "proxy_gateway_scope", "loopback_only")
	routeStrategy := normalizedRouteStrategy(plugin, cfg)
	conduitMode := normalizedConduitMode(cfg)
	providerChain := normalizedProviderChain(cfg)
	frontingPolicy := normalizedFrontingPolicy(cfg)
	lanSharing := lanSharingEnabled(cfg)
	beastMode := beastModeEnabled(cfg)
	networkPath := "plugin:" + plugin.PluginID + ":" + protocolMode
	if plugin.PluginType == "generic_proxy" {
		networkPath = "proxy:generic:" + protocolMode
	}
	attachable := routeAttachable(plugin, cfg, routeBinding, protocolMode)
	evidence := map[string]any{
		"validation_dry_run_only": true,
		"route_attachable":        attachable,
		"readiness_probe":         description.ReadinessProbe,
		"components":              description.Components,
		"required_observations":   description.Observations,
		"route_strategy":          routeStrategy,
		"provider_chain":          providerChain,
		"lan_sharing":             lanSharing,
	}
	if conduitMode != "" {
		evidence["conduit_mode"] = conduitMode
	}
	if frontingPolicy != "" {
		evidence["fronting_policy"] = frontingPolicy
	}
	if beastMode {
		evidence["establishment_intensity"] = "beast"
	}
	if cfg.Endpoint != "" {
		evidence["endpoint_present"] = true
	}
	if cfg.ConfigRef != "" {
		evidence["config_ref_present"] = true
	}
	if cfg.ProfileRef != "" {
		evidence["profile_ref_present"] = true
	}
	if cfg.CredentialRef != "" {
		evidence["credential_ref_present"] = true
	}
	for key, value := range description.Evidence {
		evidence[key] = value
	}
	routeNotReady := "PLUGIN_ROUTE_NOT_READY"
	return RouteObservationPreview{
		SchemaVersion:      1,
		ObservationID:      "preview:" + cfg.RouteID,
		RouteID:            cfg.RouteID,
		RouteType:          plugin.RouteType,
		RouteBinding:       routeBinding,
		NetworkPath:        networkPath,
		ProviderID:         nullableString(providerID),
		ProtocolMode:       nullableString(protocolMode),
		AuthMode:           nullableString(authMode),
		DNSPolicy:          dnsPolicy,
		RemoteDNSRequested: cfg.RemoteDNS,
		RemoteDNSObserved:  nil,
		SplitTunnel:        nullableString(splitTunnel),
		UpstreamMode:       nullableString(upstreamMode),
		DownstreamMode:     nullableString(downstreamMode),
		ProxyGatewayMode:   nullableString(proxyGatewayMode),
		RouteStrategy:      nullableString(routeStrategy),
		ConduitMode:        nullableString(conduitMode),
		ProviderChain:      nullableString(providerChain),
		FrontingPolicy:     nullableString(frontingPolicy),
		LANSharing:         lanSharing,
		BeastMode:          beastMode,
		ReadinessState:     "not_checked",
		Status:             "skipped",
		LatencyMS:          0,
		ErrorCode:          &routeNotReady,
		Evidence:           evidence,
	}
}

func routeAttachable(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig, routeBinding, protocolMode string) bool {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return false
	}
	if err := validateProxyEndpoint(endpoint); err != nil {
		return false
	}
	if plugin.PluginID == "generic-proxy" {
		return true
	}
	if plugin.PluginType == "psiphon" {
		if routeBinding != "tunnel_core_local_proxy" {
			return false
		}
		return allowedValue(protocolMode, "tunnel_core_supervised", "tunnel_core_library")
	}
	if plugin.PluginType == "windscribe" {
		return routeBinding == "local_proxy_gateway" && protocolMode == "local_proxy"
	}
	return false
}

func validateRouteObservationTemplate(observation RouteObservationPreview) error {
	if observation.SchemaVersion != 1 {
		return fmt.Errorf("%w: route observation template schema_version must be 1", errPluginDescriptor)
	}
	if strings.TrimSpace(observation.ObservationID) == "" || strings.TrimSpace(observation.RouteID) == "" {
		return fmt.Errorf("%w: route observation template must include observation_id and route_id", errPluginDescriptor)
	}
	if strings.TrimSpace(observation.RouteType) == "" || strings.TrimSpace(observation.RouteBinding) == "" || strings.TrimSpace(observation.NetworkPath) == "" {
		return fmt.Errorf("%w: route observation template must include route type/binding/path", errPluginDescriptor)
	}
	if strings.TrimSpace(observation.DNSPolicy) == "" {
		return fmt.Errorf("%w: route observation template must include dns_policy", errPluginDescriptor)
	}
	if observation.ReadinessState != "not_checked" {
		return fmt.Errorf("%w: route observation template readiness_state must be not_checked", errPluginDescriptor)
	}
	if observation.Status != "skipped" {
		return fmt.Errorf("%w: route observation template status must be skipped", errPluginDescriptor)
	}
	if observation.ErrorCode == nil || *observation.ErrorCode != "PLUGIN_ROUTE_NOT_READY" {
		return fmt.Errorf("%w: route observation template error_code must be PLUGIN_ROUTE_NOT_READY", errPluginDescriptor)
	}
	if observation.Evidence == nil {
		return fmt.Errorf("%w: route observation template evidence is required", errPluginDescriptor)
	}
	dryRun, ok := observation.Evidence["validation_dry_run_only"].(bool)
	if !ok || !dryRun {
		return fmt.Errorf("%w: route observation template must set validation_dry_run_only=true", errPluginDescriptor)
	}
	attachable, ok := observation.Evidence["route_attachable"].(bool)
	if !ok {
		return fmt.Errorf("%w: route observation template must include route_attachable bool", errPluginDescriptor)
	}
	if observation.RouteType != "plugin" && !attachable {
		return fmt.Errorf("%w: non-plugin route observation template must set route_attachable=true", errPluginDescriptor)
	}
	probe, ok := observation.Evidence["readiness_probe"].(string)
	if !ok || strings.TrimSpace(probe) == "" {
		return fmt.Errorf("%w: route observation template must include readiness_probe", errPluginDescriptor)
	}
	components, ok := observation.Evidence["components"].([]string)
	if !ok || len(components) == 0 {
		componentsAny, okAny := observation.Evidence["components"].([]any)
		if !okAny || len(componentsAny) == 0 {
			return fmt.Errorf("%w: route observation template must include components", errPluginDescriptor)
		}
	}
	observations, ok := observation.Evidence["required_observations"].([]string)
	if !ok || len(observations) == 0 {
		obsAny, okAny := observation.Evidence["required_observations"].([]any)
		if !okAny || len(obsAny) == 0 {
			return fmt.Errorf("%w: route observation template must include required_observations", errPluginDescriptor)
		}
	}
	return nil
}

func nullableString(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}

func normalizedAuthMode(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) string {
	mode := normalizedField(cfg, "auth_mode", "")
	if mode != "" {
		return mode
	}
	switch plugin.PluginType {
	case "windscribe":
		return "none"
	case "psiphon":
		return "config_ref"
	default:
		return "credential_ref"
	}
}

func beastModeEnabled(cfg RoutingPluginConfig) bool {
	return normalizedField(cfg, "beast_mode", "false") == "true" || normalizedField(cfg, "establishment_intensity", "normal") == "beast"
}

func normalizedConduitMode(cfg RoutingPluginConfig) string {
	return normalizedField(cfg, "conduit_mode", "")
}

func normalizedFrontingPolicy(cfg RoutingPluginConfig) string {
	if normalizedRouteStrategy(RoutingPluginDescriptor{PluginType: "psiphon"}, cfg) == "cdn_fronting" {
		return "cdn_fronting"
	}
	if strings.TrimSpace(cfg.Fields["fronting_ip_ref"]) != "" || strings.TrimSpace(cfg.Fields["cdn_fronting_ip_ref"]) != "" ||
		strings.TrimSpace(cfg.Fields["fronting_sni"]) != "" || strings.TrimSpace(cfg.Fields["cdn_fronting_sni"]) != "" {
		return "custom_cdn_fronting"
	}
	return ""
}

func isBoolText(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "true" || value == "false"
}

func isSafeHostnameLike(value string) bool {
	if len(value) > 253 || containsCRLF(value) {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '*' {
			continue
		}
		return false
	}
	return strings.Contains(value, ".") && !strings.Contains(value, "..")
}
