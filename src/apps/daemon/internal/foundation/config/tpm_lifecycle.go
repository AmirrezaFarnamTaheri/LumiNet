package config

import (
	"errors"
	"fmt"
	"time"
)

type TPMConfigSource string

const (
	TPMConfigSourceDefault     TPMConfigSource = "default"
	TPMConfigSourceEnvironment TPMConfigSource = "environment"
	TPMConfigSourceFile        TPMConfigSource = "file"
	TPMConfigSourceOperator    TPMConfigSource = "operator"
)

type TPMLifecycleInput struct {
	Source              TPMConfigSource
	ProductionAssertion bool
	RecordPath          string
	Provider            string
	AuthorizationRef    string
	Profile             string
	LegacyCutoff        *time.Time
}

type TPMLifecyclePolicy struct {
	ProductionAssertion bool
	RecordPath          string
	Provider            string
	AuthorizationRef    string
	Profile             string
	LegacyCutoff        time.Time
	effectiveSources    map[string]TPMConfigSource
}

func sourceTrust(source TPMConfigSource) int {
	switch source {
	case TPMConfigSourceOperator:
		return 3
	case TPMConfigSourceFile:
		return 2
	case TPMConfigSourceEnvironment:
		return 1
	case TPMConfigSourceDefault:
		return 0
	default:
		return -1
	}
}

// ResolveTPMLifecyclePolicy applies explicit source precedence and freezes all
// security-sensitive fields below a trusted production assertion. Environment
// input can configure development, but cannot assert or downgrade production.
func ResolveTPMLifecyclePolicy(inputs ...TPMLifecycleInput) (TPMLifecyclePolicy, error) {
	var policy TPMLifecyclePolicy
	policy.effectiveSources = make(map[string]TPMConfigSource)
	productionTrust := -1
	var productionInput TPMLifecycleInput
	for _, input := range inputs {
		trust := sourceTrust(input.Source)
		if trust < 0 {
			return TPMLifecyclePolicy{}, fmt.Errorf("unknown TPM configuration source %q", input.Source)
		}
		if input.ProductionAssertion {
			if trust < sourceTrust(TPMConfigSourceFile) {
				return TPMLifecyclePolicy{}, errors.New("production assertion requires file or operator source")
			}
			if trust > productionTrust {
				productionTrust = trust
				productionInput = input
			}
		}
	}

	for _, input := range inputs {
		trust := sourceTrust(input.Source)
		if productionTrust >= 0 && trust < productionTrust && conflictsWithProduction(input, productionInput) {
			return TPMLifecyclePolicy{}, fmt.Errorf("lower-trust %s input cannot override trusted production TPM policy", input.Source)
		}
		if input.ProductionAssertion && trust == productionTrust {
			policy.ProductionAssertion = true
			policy.effectiveSources["production_assertion"] = input.Source
		}
		applyString := func(field, value string, target *string) error {
			if value == "" {
				return nil
			}
			current, ok := policy.effectiveSources[field]
			if ok && sourceTrust(current) == trust && *target != value {
				return fmt.Errorf("conflicting equal-trust %s TPM policy inputs for %s", input.Source, field)
			}
			if !ok || sourceTrust(current) < trust {
				*target = value
				policy.effectiveSources[field] = input.Source
			}
			return nil
		}
		if err := applyString("record_path", input.RecordPath, &policy.RecordPath); err != nil {
			return TPMLifecyclePolicy{}, err
		}
		if err := applyString("provider", input.Provider, &policy.Provider); err != nil {
			return TPMLifecyclePolicy{}, err
		}
		if err := applyString("authorization_ref", input.AuthorizationRef, &policy.AuthorizationRef); err != nil {
			return TPMLifecyclePolicy{}, err
		}
		if err := applyString("profile", input.Profile, &policy.Profile); err != nil {
			return TPMLifecyclePolicy{}, err
		}
		if input.LegacyCutoff != nil {
			current, ok := policy.effectiveSources["legacy_cutoff"]
			if ok && sourceTrust(current) == trust && !policy.LegacyCutoff.Equal(input.LegacyCutoff.UTC()) {
				return TPMLifecyclePolicy{}, fmt.Errorf("conflicting equal-trust %s TPM policy inputs for legacy_cutoff", input.Source)
			}
			if !ok || sourceTrust(current) < trust {
				policy.LegacyCutoff = input.LegacyCutoff.UTC()
				policy.effectiveSources["legacy_cutoff"] = input.Source
			}
		}
	}
	if err := policy.Validate(time.Now().UTC()); err != nil {
		return TPMLifecyclePolicy{}, err
	}
	return policy, nil
}

func conflictsWithProduction(input, production TPMLifecycleInput) bool {
	return production.Provider != "" && input.Provider != "" && production.Provider != input.Provider ||
		production.AuthorizationRef != "" && input.AuthorizationRef != "" && production.AuthorizationRef != input.AuthorizationRef ||
		production.RecordPath != "" && input.RecordPath != "" && production.RecordPath != input.RecordPath ||
		production.Profile != "" && input.Profile != "" && production.Profile != input.Profile ||
		production.LegacyCutoff != nil && input.LegacyCutoff != nil && !production.LegacyCutoff.Equal(*input.LegacyCutoff)
}

func (p TPMLifecyclePolicy) Validate(now time.Time) error {
	if !p.ProductionAssertion {
		return nil
	}
	if p.RecordPath == "" || p.AuthorizationRef == "" || p.Profile == "" {
		return errors.New("trusted production TPM policy requires record path, authorization reference, and profile")
	}
	if p.Provider == "" || p.Provider == "file" {
		return errors.New("trusted production TPM policy requires an explicit native provider")
	}
	if p.LegacyCutoff.IsZero() || !p.LegacyCutoff.After(now.UTC()) {
		return errors.New("trusted production TPM policy requires a future legacy cutoff")
	}
	return nil
}

// EffectiveSourceReport is audit-safe: it reports only source identities and
// never paths, references, provider data, or secret material.
func (p TPMLifecyclePolicy) EffectiveSourceReport() map[string]TPMConfigSource {
	report := make(map[string]TPMConfigSource, len(p.effectiveSources))
	for field, source := range p.effectiveSources {
		report[field] = source
	}
	return report
}
