package config

import (
	"testing"
	"time"
)

func TestResolveTPMLifecyclePolicyRejectsLowerTrustProductionOverride(t *testing.T) {
	cutoff := time.Now().UTC().Add(time.Hour)
	trusted := TPMLifecycleInput{
		Source:              TPMConfigSourceOperator,
		ProductionAssertion: true,
		RecordPath:          "record.json",
		Provider:            "dpapi",
		AuthorizationRef:    "tpm/auth",
		Profile:             "pcr7-sha256-password-v1",
		LegacyCutoff:        &cutoff,
	}
	_, err := ResolveTPMLifecyclePolicy(trusted, TPMLifecycleInput{
		Source:           TPMConfigSourceEnvironment,
		Provider:         "file",
		AuthorizationRef: "other",
	})
	if err == nil {
		t.Fatal("lower-trust override downgraded trusted production policy")
	}
}

func TestResolveTPMLifecyclePolicyReportsEffectiveSources(t *testing.T) {
	cutoff := time.Now().UTC().Add(time.Hour)
	policy, err := ResolveTPMLifecyclePolicy(
		TPMLifecycleInput{Source: TPMConfigSourceFile, RecordPath: "record.json", Profile: "pcr7-sha256-password-v1"},
		TPMLifecycleInput{Source: TPMConfigSourceOperator, ProductionAssertion: true, Provider: "dpapi", AuthorizationRef: "tpm/auth", LegacyCutoff: &cutoff},
	)
	if err != nil {
		t.Fatal(err)
	}
	report := policy.EffectiveSourceReport()
	if report["provider"] != TPMConfigSourceOperator || report["record_path"] != TPMConfigSourceFile {
		t.Fatalf("unexpected effective sources: %#v", report)
	}
}

func TestResolveTPMLifecyclePolicyRejectsConflictingEqualTrustInputs(t *testing.T) {
	cutoff := time.Now().UTC().Add(time.Hour)
	_, err := ResolveTPMLifecyclePolicy(
		TPMLifecycleInput{
			Source:              TPMConfigSourceOperator,
			ProductionAssertion: true,
			RecordPath:          "record.json",
			Provider:            "dpapi",
			AuthorizationRef:    "tpm/auth",
			Profile:             "pcr7-sha256-password-v1",
			LegacyCutoff:        &cutoff,
		},
		TPMLifecycleInput{
			Source:   TPMConfigSourceOperator,
			Provider: "file",
		},
	)
	if err == nil {
		t.Fatal("conflicting equal-trust provider inputs were accepted")
	}
}
