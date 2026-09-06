package diagnostics

import (
	"fmt"
	"strings"
)

type RelayInspectionRequest struct {
	Transport          string `json:"transport"`
	TLSMode            string `json:"tls_mode,omitempty"`
	TrustMode          string `json:"trust_mode,omitempty"`
	STARTTLSDetection  string `json:"starttls_detection,omitempty"`
	UDPPeerModel       string `json:"udp_peer_model,omitempty"`
	MutationRequested  bool   `json:"mutation_requested,omitempty"`
	ScriptableMutation bool   `json:"scriptable_mutation,omitempty"`
}

type RelayInspectionPlan struct {
	AcceptedDesign bool     `json:"accepted_design"`
	Rejected       []string `json:"rejected"`
	Required       []string `json:"required"`
	ReadOnly       bool     `json:"read_only"`
}

func BuildRelayInspectionPlan(req RelayInspectionRequest) (RelayInspectionPlan, error) {
	transport := strings.ToLower(strings.TrimSpace(req.Transport))
	if transport != "tcp" && transport != "udp" && transport != "starttls" {
		return RelayInspectionPlan{}, fmt.Errorf("transport must be tcp, udp, or starttls")
	}
	plan := RelayInspectionPlan{ReadOnly: true, Required: []string{"bounded buffers", "explicit timeouts", "connection-scoped cancellation", "no arbitrary payload mutation"}}
	if req.MutationRequested || req.ScriptableMutation {
		plan.Rejected = append(plan.Rejected, "arbitrary/scriptable traffic mutation")
	}
	trust := strings.ToLower(strings.TrimSpace(req.TrustMode))
	if trust == "" {
		trust = "strict"
	}
	if trust != "strict" {
		plan.Rejected = append(plan.Rejected, "TLS trust disabling")
	}
	if transport == "starttls" {
		mode := strings.ToLower(strings.TrimSpace(req.STARTTLSDetection))
		if mode != "explicit-protocol" {
			plan.Rejected = append(plan.Rejected, "STARTTLS magic-byte guessing")
		} else {
			plan.Required = append(plan.Required, "protocol-explicit STARTTLS state machine")
		}
	}
	if transport == "udp" {
		peer := strings.ToLower(strings.TrimSpace(req.UDPPeerModel))
		if peer == "last-client" || peer == "single-last-client" {
			plan.Rejected = append(plan.Rejected, "global last-client UDP peer identity")
		}
		plan.Required = append(plan.Required, "per-flow UDP peer identity with expiry")
	}
	plan.AcceptedDesign = len(plan.Rejected) == 0
	return plan, nil
}
