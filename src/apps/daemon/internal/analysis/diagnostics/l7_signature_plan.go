package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const (
	maxL7Signatures      = 256
	maxL7ExpressionBytes = 1024
	maxL7SetBytes        = 128 << 10
)

type L7SignatureCandidate struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
}
type L7SignatureResult struct {
	Name             string `json:"name"`
	ExpressionSHA256 string `json:"expression_sha256,omitempty"`
	Admitted         bool   `json:"admitted"`
	Reason           string `json:"reason,omitempty"`
}
type L7SignaturePlan struct {
	Results            []L7SignatureResult `json:"results"`
	Admitted           int                 `json:"admitted"`
	Rejected           int                 `json:"rejected"`
	OfflineOnly        bool                `json:"offline_only"`
	InstallsClassifier bool                `json:"installs_classifier"`
}

// BuildL7SignaturePlan validates RE2-compatible Go regex patterns without
// inspecting traffic or installing classifiers.
func BuildL7SignaturePlan(candidates []L7SignatureCandidate) (L7SignaturePlan, error) {
	if len(candidates) == 0 || len(candidates) > maxL7Signatures {
		return L7SignaturePlan{}, fmt.Errorf("signature count must be between 1 and %d", maxL7Signatures)
	}
	total := 0
	for _, c := range candidates {
		total += len(c.Expression)
	}
	if total > maxL7SetBytes {
		return L7SignaturePlan{}, fmt.Errorf("signature set exceeds %d bytes", maxL7SetBytes)
	}
	plan := L7SignaturePlan{Results: make([]L7SignatureResult, 0, len(candidates)), OfflineOnly: true}
	seen := map[string]struct{}{}
	for _, c := range candidates {
		name := strings.TrimSpace(c.Name)
		expr := c.Expression
		result := L7SignatureResult{Name: name}
		switch {
		case name == "" || len(name) > 128:
			result.Reason = "invalid signature name"
		case len(expr) == 0:
			result.Reason = "empty expression"
		case len(expr) > maxL7ExpressionBytes:
			result.Reason = fmt.Sprintf("expression exceeds %d bytes", maxL7ExpressionBytes)
		default:
			if _, ok := seen[name]; ok {
				result.Reason = "duplicate signature name"
				break
			}
			seen[name] = struct{}{}
			re, err := regexp.Compile(expr)
			if err != nil {
				result.Reason = "invalid RE2 expression: " + err.Error()
				break
			}
			if re.MatchString("") {
				result.Reason = "expression matches empty input"
				break
			}
			d := sha256.Sum256([]byte(expr))
			result.ExpressionSHA256 = hex.EncodeToString(d[:])
			result.Admitted = true
		}
		if result.Admitted {
			plan.Admitted++
		} else {
			plan.Rejected++
		}
		plan.Results = append(plan.Results, result)
	}
	return plan, nil
}
