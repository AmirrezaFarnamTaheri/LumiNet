package routingplugin

import (
	"strings"
	"testing"
)

func mustRegistry(t *testing.T) *RoutingPluginRegistry {
	t.Helper()
	registry, err := DefaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestRoutingPluginPolicyBehaviorBaseline(t *testing.T) {
	registry := mustRegistry(t)
	tests := []struct {
		name            string
		cfg             RoutingPluginConfig
		wantErr         string
		wantMode        string
		attachable      bool
		warningContains string
	}{
		{
			name:       "generic proxy",
			cfg:        RoutingPluginConfig{SchemaVersion: 1, RouteID: "generic", PluginID: "generic-proxy", Endpoint: "socks5://127.0.0.1:1080"},
			wantMode:   "socks5",
			attachable: true,
		},
		{
			name:    "generic rejects provider field",
			cfg:     RoutingPluginConfig{SchemaVersion: 1, RouteID: "generic-bad", PluginID: "generic-proxy", Endpoint: "socks5://127.0.0.1:1080", Fields: map[string]string{"profile_type": "x"}},
			wantErr: "provider field \"profile_type\" is not supported",
		},
		{
			name:            "psiphon tunnel core",
			cfg:             RoutingPluginConfig{SchemaVersion: 1, RouteID: "psi", PluginID: "psiphon", ConfigRef: "ref:psi", Endpoint: "socks5://127.0.0.1:1090", Fields: map[string]string{"mode": "tunnel_core_supervised", "route_strategy": "auto"}},
			wantMode:        "tunnel_core_supervised",
			attachable:      true,
			warningContains: "psiphon adapter is Edge-only",
		},
		{
			name:    "psiphon rejects unknown field",
			cfg:     RoutingPluginConfig{SchemaVersion: 1, RouteID: "psi-bad-field", PluginID: "psiphon", ConfigRef: "ref:psi", Fields: map[string]string{"unknown_provider_field": "x"}},
			wantErr: "provider field \"unknown_provider_field\" is not supported",
		},
		{
			name:    "psiphon cdn fronting requires target",
			cfg:     RoutingPluginConfig{SchemaVersion: 1, RouteID: "psi-front", PluginID: "psiphon", ConfigRef: "ref:psi", Fields: map[string]string{"route_strategy": "cdn_fronting"}},
			wantErr: "cdn_fronting route strategy requires",
		},
		{
			name:            "windscribe local proxy",
			cfg:             RoutingPluginConfig{SchemaVersion: 1, RouteID: "wind", PluginID: "windscribe", Endpoint: "http://127.0.0.1:8080", Fields: map[string]string{"mode": "local_proxy", "route_strategy": "provider_default"}},
			wantMode:        "local_proxy",
			attachable:      true,
			warningContains: "windscribe adapter is Edge-only",
		},
		{
			name:    "windscribe profile mode requires ref",
			cfg:     RoutingPluginConfig{SchemaVersion: 1, RouteID: "wind-bad", PluginID: "windscribe", Fields: map[string]string{"mode": "wireguard"}},
			wantErr: "windscribe protocol mode requires profile_ref",
		},
		{
			name:    "windscribe login remains android owned",
			cfg:     RoutingPluginConfig{SchemaVersion: 1, RouteID: "wind-login", PluginID: "windscribe", Fields: map[string]string{"auth_mode": "wsnet_login_required"}},
			wantErr: "windscribe wsnet login flow belongs to Android session ownership",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateRoutingPluginConfig(registry, tt.cfg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.ProtocolMode != tt.wantMode {
				t.Fatalf("protocol mode = %q, want %q", got.ProtocolMode, tt.wantMode)
			}
			if got.Attachable != tt.attachable {
				t.Fatalf("attachable = %v, want %v", got.Attachable, tt.attachable)
			}
			if tt.warningContains != "" && !strings.Contains(strings.Join(got.Warnings, "\n"), tt.warningContains) {
				t.Fatalf("warnings = %v, missing %q", got.Warnings, tt.warningContains)
			}
		})
	}
}

func TestRoutingPluginPolicyRedactionBaseline(t *testing.T) {
	registry := mustRegistry(t)
	result, err := ValidateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "wind-redact",
		PluginID:      "windscribe",
		CredentialRef: "ref:session",
		Fields: map[string]string{
			"auth_mode":   "wsnet_session_ref",
			"session_ref": "session-42",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RedactedConfig["credential_ref"] != "ref:session" {
		t.Fatalf("credential_ref unexpectedly changed: %q", result.RedactedConfig["credential_ref"])
	}
}

func TestRoutingPluginPoliciesProvideValidUniqueDefaultDescriptors(t *testing.T) {
	seenTypes := map[string]bool{}
	seenIDs := map[string]bool{}
	for _, policy := range routingPluginPolicies() {
		descriptor := policy.defaultDescriptor()
		if err := validateRoutingPluginDescriptor(descriptor); err != nil {
			t.Fatalf("default descriptor %q is invalid: %v", descriptor.PluginID, err)
		}
		if seenTypes[descriptor.PluginType] {
			t.Fatalf("duplicate default plugin type %q", descriptor.PluginType)
		}
		if seenIDs[descriptor.PluginID] {
			t.Fatalf("duplicate default plugin id %q", descriptor.PluginID)
		}
		seenTypes[descriptor.PluginType] = true
		seenIDs[descriptor.PluginID] = true
	}
}

func TestRoutingPluginPoliciesEnforceDescriptorSecretPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy routingPluginPolicy
		secret string
		want   string
	}{
		{name: "psiphon", policy: psiphonPolicy{}, secret: "credential_ref_only", want: "psiphon must use imported_config_ref secret policy"},
		{name: "windscribe", policy: windscribePolicy{}, secret: "external_app", want: "windscribe must use credential_ref_only secret policy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descriptor := tt.policy.defaultDescriptor()
			descriptor.SecretPolicy = tt.secret
			err := tt.policy.validateDescriptor(descriptor)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
