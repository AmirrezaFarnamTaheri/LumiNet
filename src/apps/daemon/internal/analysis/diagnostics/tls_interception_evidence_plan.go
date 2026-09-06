package diagnostics

import (
	"fmt"
	"sort"
	"strings"
)

const maxTLSInterceptionEvidenceComponents = 32

type TLSInterceptionComponentEvidence struct {
	Component string `json:"component"`
	Match     string `json:"match"`
}

type TLSInterceptionEvidenceRequest struct {
	Components          []TLSInterceptionComponentEvidence `json:"components,omitempty"`
	ExpectedGrade       string                             `json:"expected_grade,omitempty"`
	ObservedGrade       string                             `json:"observed_grade,omitempty"`
	ExpectedPFS         *bool                              `json:"expected_pfs,omitempty"`
	ObservedPFS         *bool                              `json:"observed_pfs,omitempty"`
	WeakCiphersDetected bool                               `json:"weak_ciphers_detected,omitempty"`
}

type TLSInterceptionEvidencePlan struct {
	WorstMatch                    string   `json:"worst_match"`
	MismatchedComponents          []string `json:"mismatched_components"`
	ExpectedGrade                 string   `json:"expected_grade,omitempty"`
	ObservedGrade                 string   `json:"observed_grade,omitempty"`
	GradeRegressed                bool     `json:"grade_regressed"`
	PFSLost                       bool     `json:"pfs_lost"`
	WeakCiphersDetected           bool     `json:"weak_ciphers_detected"`
	Suspicious                    bool     `json:"suspicious"`
	Reasons                       []string `json:"reasons"`
	Invariants                    []string `json:"invariants"`
	ReadOnly                      bool     `json:"read_only"`
	PerformsNetworkIO             bool     `json:"performs_network_io"`
	UsesFingerprintDatabase       bool     `json:"uses_fingerprint_database"`
	IdentifiesInterceptionProduct bool     `json:"identifies_interception_product"`
}

func normalizeTLSInterceptionMatch(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "empty", "":
		return "empty", true
	case "possible":
		return "possible", true
	case "unlikely":
		return "unlikely", true
	case "impossible":
		return "impossible", true
	default:
		return "", false
	}
}

func normalizeTLSGrade(raw string) (string, bool) {
	grade := strings.ToUpper(strings.TrimSpace(raw))
	switch grade {
	case "", "A", "B", "C", "F":
		return grade, true
	default:
		return "", false
	}
}

func tlsGradeStrength(grade string) int {
	switch grade {
	case "A":
		return 4
	case "B":
		return 3
	case "C":
		return 2
	case "F":
		return 1
	default:
		return 0
	}
}

func BuildTLSInterceptionEvidencePlan(req TLSInterceptionEvidenceRequest) (TLSInterceptionEvidencePlan, error) {
	if len(req.Components) > maxTLSInterceptionEvidenceComponents {
		return TLSInterceptionEvidencePlan{}, fmt.Errorf("TLS interception evidence components must be <=%d", maxTLSInterceptionEvidenceComponents)
	}
	expectedGrade, ok := normalizeTLSGrade(req.ExpectedGrade)
	if !ok {
		return TLSInterceptionEvidencePlan{}, fmt.Errorf("expected_grade must be A, B, C, or F")
	}
	observedGrade, ok := normalizeTLSGrade(req.ObservedGrade)
	if !ok {
		return TLSInterceptionEvidencePlan{}, fmt.Errorf("observed_grade must be A, B, C, or F")
	}
	if (expectedGrade == "") != (observedGrade == "") {
		return TLSInterceptionEvidencePlan{}, fmt.Errorf("expected_grade and observed_grade must be supplied together")
	}
	if (req.ExpectedPFS == nil) != (req.ObservedPFS == nil) {
		return TLSInterceptionEvidencePlan{}, fmt.Errorf("expected_pfs and observed_pfs must be supplied together")
	}
	if len(req.Components) == 0 && expectedGrade == "" && req.ExpectedPFS == nil && !req.WeakCiphersDetected {
		return TLSInterceptionEvidencePlan{}, fmt.Errorf("at least one TLS interception evidence signal is required")
	}

	seen := map[string]bool{}
	mismatches := []string{}
	worst := "empty"
	worstRank := 0
	for _, item := range req.Components {
		component := strings.ToLower(strings.TrimSpace(item.Component))
		if component == "" || len(component) > 64 {
			return TLSInterceptionEvidencePlan{}, fmt.Errorf("TLS evidence component names must be non-empty and <=64 bytes")
		}
		if seen[component] {
			return TLSInterceptionEvidencePlan{}, fmt.Errorf("duplicate TLS evidence component %q", component)
		}
		seen[component] = true
		match, ok := normalizeTLSInterceptionMatch(item.Match)
		if !ok {
			return TLSInterceptionEvidencePlan{}, fmt.Errorf("unsupported TLS evidence match %q", item.Match)
		}
		rank := map[string]int{"empty": 0, "possible": 1, "unlikely": 2, "impossible": 3}[match]
		if rank > worstRank {
			worstRank = rank
			worst = match
		}
		if match == "unlikely" || match == "impossible" {
			mismatches = append(mismatches, component)
		}
	}
	sort.Strings(mismatches)

	gradeRegressed := expectedGrade != "" && tlsGradeStrength(observedGrade) < tlsGradeStrength(expectedGrade)
	pfsLost := req.ExpectedPFS != nil && *req.ExpectedPFS && !*req.ObservedPFS
	suspicious := worst == "unlikely" || worst == "impossible" || gradeRegressed || pfsLost || req.WeakCiphersDetected
	reasons := []string{}
	if worst == "impossible" {
		reasons = append(reasons, "one or more observed TLS components are incompatible with the expected client evidence")
	} else if worst == "unlikely" {
		reasons = append(reasons, "one or more observed TLS components require an unlikely expected-client configuration")
	}
	if gradeRegressed {
		reasons = append(reasons, fmt.Sprintf("observed TLS security grade regressed from %s to %s", expectedGrade, observedGrade))
	}
	if pfsLost {
		reasons = append(reasons, "perfect forward secrecy was expected but is absent in observed evidence")
	}
	if req.WeakCiphersDetected {
		reasons = append(reasons, "weak cipher evidence is present")
	}
	if !suspicious {
		reasons = append(reasons, "caller-supplied TLS evidence contains no modeled interception anomaly")
	}

	return TLSInterceptionEvidencePlan{
		WorstMatch:           worst,
		MismatchedComponents: mismatches,
		ExpectedGrade:        expectedGrade,
		ObservedGrade:        observedGrade,
		GradeRegressed:       gradeRegressed,
		PFSLost:              pfsLost,
		WeakCiphersDetected:  req.WeakCiphersDetected,
		Suspicious:           suspicious,
		Reasons:              reasons,
		Invariants: []string{
			"component mismatch, grade regression, PFS loss, and weak-cipher evidence remain separate signals",
			"caller-supplied evidence can flag an anomaly but cannot identify a particular interception product",
			"historical fingerprint databases are not imported as current interception authority",
			"this planner performs no packet capture, TLS handshake, certificate installation, or network request",
		},
		ReadOnly:                      true,
		PerformsNetworkIO:             false,
		UsesFingerprintDatabase:       false,
		IdentifiesInterceptionProduct: false,
	}, nil
}
