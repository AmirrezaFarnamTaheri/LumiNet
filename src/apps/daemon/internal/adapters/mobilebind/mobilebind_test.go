package mobilebind

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/maybeknott/luminet/internal/runtime/proxy"
	"github.com/maybeknott/luminet/internal/runtime/safety"
)

func TestStatusJSONUsesRedactedEvasionSnapshot(t *testing.T) {
	manager := proxy.GetEvasionManager()
	manager.Stop()
	t.Cleanup(manager.Stop)

	cfg := proxy.DefaultEvasionConfig()
	cfg.Port = 0
	cfg.CovertGsaKey = "mobile-gsa-secret"
	cfg.CovertGdocsAccessToken = "mobile-gdocs-secret"
	if err := manager.Start(&cfg); err != nil {
		t.Fatalf("start evasion manager: %v", err)
	}

	status, err := StatusJSON()
	if err != nil {
		t.Fatalf("StatusJSON: %v", err)
	}
	if strings.Contains(status, "mobile-gsa-secret") || strings.Contains(status, "mobile-gdocs-secret") {
		t.Fatalf("StatusJSON exposed evasion credentials: %s", status)
	}
	if !strings.Contains(status, "[REDACTED]") {
		t.Fatalf("StatusJSON did not preserve explicit redaction marker: %s", status)
	}
}

func TestApplySafetyPolicyJSONUsesSharedSafetyGovernor(t *testing.T) {
	governor := safety.GetGovernor()
	_ = governor.Close()
	governor.AuditLogPath = t.TempDir() + "/safety.log"
	t.Cleanup(func() { _ = governor.Close() })

	resultJSON, err := ApplySafetyPolicyJSON(`{"target":"127.0.0.1","respect_safety":true,"authorization_confirmed":false,"rate_ceiling":1000}`)
	if err != nil {
		t.Fatalf("ApplySafetyPolicyJSON: %v", err)
	}
	var result struct {
		Approved bool   `json:"approved"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Approved || !strings.Contains(result.Error, "blocked under default safety policy") {
		t.Fatalf("mobile safety result diverged from SafetyGovernor: %+v", result)
	}
}

func TestGetSafetyPolicyJSONUsesSharedDefaultsAndAuditPath(t *testing.T) {
	governor := safety.GetGovernor()
	_ = governor.Close()
	governor.AuditLogPath = t.TempDir() + "/mobile-safety.log"

	statusJSON, err := GetSafetyPolicyJSON()
	if err != nil {
		t.Fatalf("GetSafetyPolicyJSON: %v", err)
	}
	var status struct {
		RespectSafety          bool   `json:"respect_safety"`
		AuthorizationConfirmed bool   `json:"authorization_confirmed"`
		RateCeiling            int    `json:"rate_ceiling"`
		AuditLogPath           string `json:"audit_log_path"`
	}
	if err := json.Unmarshal([]byte(statusJSON), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	defaults := safety.DefaultSettings()
	if status.RespectSafety != defaults.RespectSafety || status.AuthorizationConfirmed != defaults.AuthorizationConfirmed || status.RateCeiling != defaults.RateCeiling {
		t.Fatalf("mobile safety defaults diverged from proxy owner: %+v vs %+v", status, defaults)
	}
	if status.AuditLogPath != governor.AuditLogPath {
		t.Fatalf("mobile safety audit path = %q, want %q", status.AuditLogPath, governor.AuditLogPath)
	}
}
