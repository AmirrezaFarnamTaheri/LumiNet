package diagnostics

import (
	"fmt"
	"strings"
)

type TailnetTransactionPlanRequest struct {
	Operation string `json:"operation"`
	ETag      string `json:"etag,omitempty"`
	Validate  bool   `json:"validate,omitempty"`
	TargetID  string `json:"target_id,omitempty"`
}

type TailnetTransactionPlan struct {
	Operation          string   `json:"operation"`
	Steps              []string `json:"steps"`
	RequiresETag       bool     `json:"requires_etag"`
	ValidationOnly     bool     `json:"validation_only"`
	PatchSemantics     bool     `json:"patch_semantics"`
	ReplaceSemantics   bool     `json:"replace_semantics"`
	SensitiveResult    bool     `json:"sensitive_result"`
	CredentialAccepted bool     `json:"credential_accepted"`
	MakesAPIRequest    bool     `json:"makes_api_request"`
	Invariants         []string `json:"invariants"`
}

func BuildTailnetTransactionPlan(req TailnetTransactionPlanRequest) (TailnetTransactionPlan, error) {
	op := strings.ToLower(strings.TrimSpace(req.Operation))
	plan := TailnetTransactionPlan{Operation: op}
	switch op {
	case "acl-validate":
		plan.ValidationOnly = true
		plan.Steps = []string{"validate proposed policy against current schema", "return validation evidence only"}
	case "dns-patch":
		plan.RequiresETag, plan.PatchSemantics = true, true
		plan.Steps = []string{"read authoritative DNS state and ETag", "validate intended field delta", "compare If-Match ETag", "patch only declared DNS fields"}
	case "dns-replace":
		plan.RequiresETag, plan.ReplaceSemantics = true, true
		plan.Steps = []string{"read authoritative DNS state and ETag", "validate complete replacement payload", "compare If-Match ETag", "replace complete DNS configuration"}
	case "device-route":
		plan.RequiresETag = true
		if strings.TrimSpace(req.TargetID) == "" {
			return TailnetTransactionPlan{}, fmt.Errorf("device-route requires target_id")
		}
		plan.Steps = []string{"read target device route state and revision evidence", "validate route intent", "compare revision/ETag", "apply only target device route change"}
	case "key-create":
		plan.SensitiveResult = true
		plan.Steps = []string{"validate key capabilities and expiry", "create key exactly once", "return secret only to dedicated secret owner"}
	case "webhook-secret-rotate":
		plan.RequiresETag, plan.SensitiveResult = true, true
		if strings.TrimSpace(req.TargetID) == "" {
			return TailnetTransactionPlan{}, fmt.Errorf("webhook-secret-rotate requires target_id")
		}
		plan.Steps = []string{"read webhook revision evidence", "compare revision/ETag", "rotate webhook secret once", "invalidate prior secret after acknowledged replacement"}
	default:
		return TailnetTransactionPlan{}, fmt.Errorf("unsupported tailnet transaction %q", req.Operation)
	}
	if plan.RequiresETag && strings.TrimSpace(req.ETag) == "" {
		return TailnetTransactionPlan{}, fmt.Errorf("tailnet transaction %q requires an explicit ETag/revision precondition", op)
	}
	if req.Validate {
		plan.ValidationOnly = true
		plan.Steps = append([]string{"validate requested transaction without mutation"}, plan.Steps...)
	}
	plan.Invariants = []string{
		"the planner accepts no Tailnet API token or credential",
		"read-modify-write operations require an explicit revision/ETag precondition",
		"DNS patch and DNS replacement remain distinct transaction shapes",
		"key and webhook-secret material is classified sensitive and never synthesized by this planner",
		"the planner performs no API request and commits no remote mutation",
	}
	return plan, nil
}
