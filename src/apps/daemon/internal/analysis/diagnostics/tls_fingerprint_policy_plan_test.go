package diagnostics

import (
	"testing"
)

func TestBuildTLSFingerprintPolicyPlan_Valid(t *testing.T) {
	req := TLSFingerprintPolicyRequest{
		Candidates:     []string{"chrome", "firefox", "safari"},
		MaxTrials:      3,
		RequiredALPN:   []string{"h2", "http/1.1"},
		ReuseKnownGood: true,
	}

	plan, err := BuildTLSFingerprintPolicyPlan(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(plan.OrderedProfiles) != 3 {
		t.Errorf("expected 3 profiles, got %d", len(plan.OrderedProfiles))
	}
	if plan.MaxTrials != 3 {
		t.Errorf("expected max_trials 3, got %d", plan.MaxTrials)
	}
	if len(plan.RequiredALPN) != 2 {
		t.Errorf("expected 2 ALPN entries, got %d", len(plan.RequiredALPN))
	}
}

func TestBuildTLSFingerprintPolicyPlan_InvalidProfile(t *testing.T) {
	req := TLSFingerprintPolicyRequest{
		Candidates: []string{"unknown_browser"},
	}

	_, err := BuildTLSFingerprintPolicyPlan(req)
	if err == nil {
		t.Fatalf("expected error for unknown browser, got nil")
	}
}

func TestBuildTLSFingerprintPolicyPlan_WeakCiphersRejected(t *testing.T) {
	req := TLSFingerprintPolicyRequest{
		Candidates:       []string{"chrome"},
		AllowWeakCiphers: true,
	}

	_, err := BuildTLSFingerprintPolicyPlan(req)
	if err == nil {
		t.Fatalf("expected rejection of weak ciphers, got nil")
	}
}
