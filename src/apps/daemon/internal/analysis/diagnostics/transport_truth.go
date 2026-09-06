package diagnostics

import (
	"fmt"
	"math"
	"strings"
)

const maxTransportTruthBurst = 10000

type TransportTruthRequest struct {
	HandshakeOK           bool    `json:"handshake_ok"`
	BurstSize             int     `json:"burst_size"`
	FirstBurstSuccesses   int     `json:"first_burst_successes"`
	SecondBurstSuccesses  int     `json:"second_burst_successes"`
	MinimumDeliveryPct    float64 `json:"minimum_delivery_pct,omitempty"`
	AdvertisedCountry     string  `json:"advertised_country,omitempty"`
	MeasuredEgressCountry string  `json:"measured_egress_country,omitempty"`
}

type TransportTruthPlan struct {
	Verdict                string   `json:"verdict"`
	Connected              bool     `json:"connected"`
	HandshakeOK            bool     `json:"handshake_ok"`
	FirstBurstDeliveryPct  float64  `json:"first_burst_delivery_pct"`
	SecondBurstDeliveryPct float64  `json:"second_burst_delivery_pct"`
	MinimumDeliveryPct     float64  `json:"minimum_delivery_pct"`
	AdvertisedCountry      string   `json:"advertised_country,omitempty"`
	MeasuredEgressCountry  string   `json:"measured_egress_country,omitempty"`
	LocationVerdict        string   `json:"location_verdict"`
	Evidence               []string `json:"evidence"`
	SafetyBoundary         string   `json:"safety_boundary"`
}

func BuildTransportTruthPlan(req TransportTruthRequest) (TransportTruthPlan, error) {
	if req.BurstSize < 1 || req.BurstSize > maxTransportTruthBurst {
		return TransportTruthPlan{}, fmt.Errorf("burst size must be between 1 and %d", maxTransportTruthBurst)
	}
	if req.FirstBurstSuccesses < 0 || req.FirstBurstSuccesses > req.BurstSize || req.SecondBurstSuccesses < 0 || req.SecondBurstSuccesses > req.BurstSize {
		return TransportTruthPlan{}, fmt.Errorf("burst successes must be between zero and burst size")
	}
	threshold := req.MinimumDeliveryPct
	if threshold == 0 {
		threshold = 80
	}
	if math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold <= 0 || threshold > 100 {
		return TransportTruthPlan{}, fmt.Errorf("minimum delivery must be finite and between 0 and 100")
	}
	advertised, err := normalizeCountryCode(req.AdvertisedCountry)
	if err != nil {
		return TransportTruthPlan{}, fmt.Errorf("advertised country: %w", err)
	}
	measured, err := normalizeCountryCode(req.MeasuredEgressCountry)
	if err != nil {
		return TransportTruthPlan{}, fmt.Errorf("measured egress country: %w", err)
	}
	first := round2(float64(req.FirstBurstSuccesses) * 100 / float64(req.BurstSize))
	second := round2(float64(req.SecondBurstSuccesses) * 100 / float64(req.BurstSize))
	plan := TransportTruthPlan{
		HandshakeOK: req.HandshakeOK, FirstBurstDeliveryPct: first, SecondBurstDeliveryPct: second,
		MinimumDeliveryPct: threshold, AdvertisedCountry: advertised, MeasuredEgressCountry: measured,
		LocationVerdict: "unknown", SafetyBoundary: "read-only evidence; handshake or advertised metadata never grants connectivity authority",
	}
	switch {
	case !req.HandshakeOK:
		plan.Verdict = "handshake-failed"
		plan.Evidence = append(plan.Evidence, "transport handshake was not established")
	case req.FirstBurstSuccesses == 0:
		plan.Verdict = "handshake-only"
		plan.Evidence = append(plan.Evidence, "handshake succeeded but no in-tunnel payload was observed")
	case req.SecondBurstSuccesses == 0:
		plan.Verdict = "transient"
		plan.Evidence = append(plan.Evidence, "payload flowed in the first burst but durability was not demonstrated")
	case first < threshold || second < threshold:
		plan.Verdict = "torn-down"
		plan.Evidence = append(plan.Evidence, "in-tunnel delivery fell below the sustained-delivery threshold")
	default:
		plan.Verdict = "durable"
		plan.Connected = true
		plan.Evidence = append(plan.Evidence, "two payload bursts met the sustained-delivery threshold")
	}
	switch {
	case measured == "" && advertised == "":
		plan.LocationVerdict = "unknown"
	case measured == "":
		plan.LocationVerdict = "advertised-only"
		plan.Evidence = append(plan.Evidence, "egress location is advertised metadata only; it was not measured")
	case advertised == "":
		plan.LocationVerdict = "measured"
		plan.Evidence = append(plan.Evidence, "egress location was measured without an advertised comparison")
	case advertised == measured:
		plan.LocationVerdict = "match"
		plan.Evidence = append(plan.Evidence, "measured egress location matches advertised metadata")
	default:
		plan.LocationVerdict = "mismatch"
		plan.Evidence = append(plan.Evidence, "measured egress location disagrees with advertised metadata")
	}
	return plan, nil
}

func normalizeCountryCode(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	if len(value) != 2 || value[0] < 'A' || value[0] > 'Z' || value[1] < 'A' || value[1] > 'Z' {
		return "", fmt.Errorf("country code must be a two-letter ISO-style code")
	}
	return value, nil
}

func round2(value float64) float64 { return math.Round(value*100) / 100 }
