package dnstunnel

import (
	"fmt"
	"math"
	"strings"
)

const (
	MaxDNSNameBytes  = 253
	MaxLabelBytes    = 63
	DefaultUDPBudget = 1232
	FrameHeaderBytes = 20
)

type PlanRequest struct {
	Suffix              string                `json:"suffix"`
	PayloadBytes        int                   `json:"payload_bytes"`
	UDPBudget           int                   `json:"udp_budget,omitempty"`
	Encoding            string                `json:"encoding,omitempty"`
	Preset              string                `json:"preset,omitempty"`
	ObservedLossPct     *float64              `json:"observed_loss_pct,omitempty"`
	FECDataShards       *int                  `json:"fec_data_shards,omitempty"`
	FECBaseParity       *int                  `json:"fec_base_parity,omitempty"`
	FECLossThresholdPct *float64              `json:"fec_loss_threshold_pct,omitempty"`
	SuperLossFloorPct   *float64              `json:"super_loss_floor_pct,omitempty"`
	SuperLossCeilPct    *float64              `json:"super_loss_ceil_pct,omitempty"`
	RecoveryTargetPct   *float64              `json:"recovery_target_pct,omitempty"`
	PreferredTransport  string                `json:"preferred_transport,omitempty"`
	Resolvers           []ResolverObservation `json:"resolvers,omitempty"`
}
type Plan struct {
	Suffix               string          `json:"suffix"`
	Encoding             string          `json:"encoding"`
	UDPBudget            int             `json:"udp_budget"`
	QueryEncodedChars    int             `json:"query_encoded_chars"`
	QueryPayloadBytes    int             `json:"query_payload_bytes"`
	ResponsePayloadBytes int             `json:"response_payload_bytes"`
	FramePayloadBytes    int             `json:"frame_payload_bytes"`
	Fragments            int             `json:"fragments"`
	EstimatedQueries     int             `json:"estimated_queries"`
	Reliability          ReliabilityPlan `json:"reliability"`
}

func BuildPlan(req PlanRequest) (Plan, error) {
	reliability, err := buildReliabilityPlan(req)
	if err != nil {
		return Plan{}, err
	}
	suffix := strings.Trim(strings.TrimSpace(req.Suffix), ".")
	if suffix == "" {
		return Plan{}, fmt.Errorf("DNS tunnel suffix is required")
	}
	if len(suffix) > 200 {
		return Plan{}, fmt.Errorf("DNS tunnel suffix too long")
	}
	for _, label := range strings.Split(suffix, ".") {
		if label == "" || len(label) > MaxLabelBytes {
			return Plan{}, fmt.Errorf("invalid DNS label in suffix")
		}
	}
	if req.PayloadBytes < 0 || req.PayloadBytes > 64*1024*1024 {
		return Plan{}, fmt.Errorf("payload size out of range")
	}
	budget := req.UDPBudget
	if budget == 0 {
		budget = DefaultUDPBudget
	}
	if budget < 512 || budget > 4096 {
		return Plan{}, fmt.Errorf("UDP budget must be between 512 and 4096")
	}
	enc := strings.ToLower(strings.TrimSpace(req.Encoding))
	if enc == "" {
		enc = "base32"
	}
	var ratio float64
	switch enc {
	case "base32":
		ratio = 8.0 / 5.0
	case "base64url":
		ratio = 4.0 / 3.0
	default:
		return Plan{}, fmt.Errorf("unsupported DNS tunnel encoding %q", enc)
	}
	suffixWire := len(suffix) + 2
	maxChars := MaxDNSNameBytes - suffixWire - 1
	if maxChars < 16 {
		return Plan{}, fmt.Errorf("suffix leaves insufficient query payload capacity")
	}
	labels := (maxChars + MaxLabelBytes - 1) / MaxLabelBytes
	maxChars -= labels
	if maxChars < 1 {
		maxChars = 1
	}
	queryBytes := int(math.Floor(float64(maxChars) / ratio))
	responseOverhead := 12 + 32 + suffixWire
	responseBytes := budget - responseOverhead - 8
	if responseBytes < 1 {
		responseBytes = 1
	}
	framePayload := queryBytes - FrameHeaderBytes
	if responseBytes-FrameHeaderBytes < framePayload {
		framePayload = responseBytes - FrameHeaderBytes
	}
	if framePayload < 1 {
		return Plan{}, fmt.Errorf("DNS budget leaves no frame payload")
	}
	fragments := 0
	if req.PayloadBytes > 0 {
		fragments = (req.PayloadBytes + framePayload - 1) / framePayload
	}
	return Plan{Suffix: suffix, Encoding: enc, UDPBudget: budget, QueryEncodedChars: maxChars, QueryPayloadBytes: queryBytes, ResponsePayloadBytes: responseBytes, FramePayloadBytes: framePayload, Fragments: fragments, EstimatedQueries: fragments, Reliability: reliability}, nil
}
