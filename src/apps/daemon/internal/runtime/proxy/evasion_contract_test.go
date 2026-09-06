package proxy

import (
	"strings"
	"testing"
)

func TestValidateEvasionConfigRejectsNonProductionCovertModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  EvasionConfig
	}{
		{name: "dns tunnel is simulation only", cfg: EvasionConfig{CovertMode: "dnstunnel", CovertDnsDomain: "tunnel.example"}},
		{name: "gdocs without token would simulate", cfg: EvasionConfig{CovertMode: "gdocs", CovertGdocsFolderId: "folder"}},
		{name: "gdrive without token would simulate", cfg: EvasionConfig{CovertMode: "gdrive", CovertGdocsFolderId: "folder"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := validateEvasionConfig(tt.cfg); err == nil {
				t.Fatalf("validateEvasionConfig(%q) = nil, want capability error", tt.cfg.CovertMode)
			}
		})
	}
}

func TestValidateEvasionConfigRequiresModeConfiguration(t *testing.T) {
	t.Parallel()

	tests := []EvasionConfig{
		{CovertMode: "serverless"},
		{CovertMode: "edge"},
		{CovertMode: "gsa"},
		{CovertMode: "wstunnel"},
		{CovertMode: "ssh"},
		{CovertMode: "kcp"},
		{CovertMode: "tuic"},
		{CovertMode: "not-a-mode"},
	}
	for _, cfg := range tests {
		if err := validateEvasionConfig(cfg); err == nil {
			t.Fatalf("validateEvasionConfig(%q) = nil, want error", cfg.CovertMode)
		}
	}
}

func TestRedactedEvasionConfigHidesSecrets(t *testing.T) {
	t.Parallel()

	cfg := EvasionConfig{
		CovertGsaKey:           "gsa-secret",
		CovertGdocsAccessToken: "gdocs-secret",
		CovertCfg: CovertTransportConfig{
			SshPass:          "ssh-password",
			SshKey:           "ssh-key",
			SshKeyPassphrase: "ssh-key-passphrase",
			TuicToken:        "tuic-token",
		},
	}
	redacted := redactedEvasionConfig(cfg)
	serialized := strings.Join([]string{
		redacted.CovertGsaKey,
		redacted.CovertGdocsAccessToken,
		redacted.CovertCfg.SshPass,
		redacted.CovertCfg.SshKey,
		redacted.CovertCfg.SshKeyPassphrase,
		redacted.CovertCfg.TuicToken,
	}, "|")
	if strings.Contains(serialized, "secret") || strings.Contains(serialized, "password") || strings.Contains(serialized, "ssh-key") || strings.Contains(serialized, "tuic-token") {
		t.Fatalf("redacted config leaked secret material: %q", serialized)
	}
	if strings.Count(serialized, "[REDACTED]") != 6 {
		t.Fatalf("redacted config = %q, want six redaction markers", serialized)
	}
}

func TestRestoreRedactedSecretsUsesCurrentRuntimeSecrets(t *testing.T) {
	mgr := &EvasionTunnelManager{}
	current := DefaultEvasionConfig()
	current.CovertGsaKey = "gsa-secret"
	current.CovertGdocsAccessToken = "docs-secret"
	current.CovertCfg.SshPass = "ssh-pass"
	current.CovertCfg.SshKey = "ssh-key"
	current.CovertCfg.SshKeyPassphrase = "ssh-key-passphrase"
	current.CovertCfg.TuicToken = "tuic-secret"
	mgr.config.Store(&current)

	candidate := DefaultEvasionConfig()
	candidate.CovertGsaKey = redactedEvasionSecret
	candidate.CovertGdocsAccessToken = redactedEvasionSecret
	candidate.CovertCfg.SshPass = redactedEvasionSecret
	candidate.CovertCfg.SshKey = "replacement-key"
	candidate.CovertCfg.SshKeyPassphrase = redactedEvasionSecret
	candidate.CovertCfg.TuicToken = redactedEvasionSecret

	restored := mgr.RestoreRedactedSecrets(candidate)
	if restored.CovertGsaKey != "gsa-secret" || restored.CovertGdocsAccessToken != "docs-secret" {
		t.Fatalf("top-level secrets were not restored: %+v", restored)
	}
	if restored.CovertCfg.SshPass != "ssh-pass" || restored.CovertCfg.SshKeyPassphrase != "ssh-key-passphrase" || restored.CovertCfg.TuicToken != "tuic-secret" {
		t.Fatalf("covert secrets were not restored: %+v", restored.CovertCfg)
	}
	if restored.CovertCfg.SshKey != "replacement-key" {
		t.Fatalf("non-redacted secret was overwritten: %q", restored.CovertCfg.SshKey)
	}
}

func TestPostRefactor225CovertTUICFailsClosedBecauseTUICRequiresQUIC(t *testing.T) {
	cfg := DefaultEvasionConfig()
	cfg.CovertMode = "tuic"
	cfg.CovertCfg.SshHost = "example.test:443"
	if err := validateEvasionConfig(cfg); err == nil || !strings.Contains(err.Error(), "requires a QUIC transport") {
		t.Fatalf("validateEvasionConfig(tuic) err=%v, want explicit QUIC transport rejection", err)
	}
}
