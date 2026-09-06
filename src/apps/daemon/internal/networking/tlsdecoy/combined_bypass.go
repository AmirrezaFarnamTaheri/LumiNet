package tlsdecoy

import (
	"bytes"
	"errors"
	"time"
)

// BypassMode identifies the evasion strategy to apply.
type BypassMode string

const (
	BypassModeDirect            BypassMode = "Direct"
	BypassModeFakeSniDecoy      BypassMode = "FakeSniDecoy"
	BypassModeSniFragment       BypassMode = "SniFragment"
	BypassModeCombinedTtlDecoy  BypassMode = "CombinedTtlDecoy"
	BypassModeCombinedRawDesync BypassMode = "CombinedRawDesync"
)

// CombinedBypassConfig configures multi-layer DPI evasion.
type CombinedBypassConfig struct {
	Mode             BypassMode `json:"mode"`
	FakeSNI          string     `json:"fake_sni"`
	UseTTLTrick      bool       `json:"use_ttl_trick"`
	TTLHops          int        `json:"ttl_hops"`
	FragmentStrategy string     `json:"fragment_strategy"`
	FragmentDelayMs  int        `json:"fragment_delay_ms"`
}

// DefaultCombinedBypassConfig returns production-ready defaults.
func DefaultCombinedBypassConfig() CombinedBypassConfig {
	return CombinedBypassConfig{
		Mode:             BypassModeCombinedTtlDecoy,
		FakeSNI:          "auth.vercel.com",
		UseTTLTrick:      true,
		TTLHops:          2,
		FragmentStrategy: "sni_split",
		FragmentDelayMs:  10,
	}
}

// DecoyProbeSpec defines a low-TTL decoy packet to poison intermediate DPI state.
type DecoyProbeSpec struct {
	TTL     int    `json:"ttl"`
	Payload []byte `json:"payload"`
}

// FragmentSpec represents a single TLS record/TCP segment with optional delay.
type FragmentSpec struct {
	Payload []byte `json:"payload"`
	DelayMs int    `json:"delay_ms"`
}

// PreparedEvasionPlan holds the structured execution plan for combined evasion.
type PreparedEvasionPlan struct {
	DecoyProbe *DecoyProbeSpec `json:"decoy_probe,omitempty"`
	Fragments  []FragmentSpec  `json:"fragments"`
}

// CombinedBypassPlanner plans multi-layer evasion sequences.
type CombinedBypassPlanner struct{}

// NewCombinedBypassPlanner creates a planner.
func NewCombinedBypassPlanner() *CombinedBypassPlanner {
	return &CombinedBypassPlanner{}
}

// Plan builds a combined evasion plan given real and fake ClientHello payloads.
func (p *CombinedBypassPlanner) Plan(realHello, fakeHello []byte, cfg CombinedBypassConfig) (*PreparedEvasionPlan, error) {
	if len(realHello) == 0 {
		return nil, errors.New("real ClientHello cannot be empty")
	}

	plan := &PreparedEvasionPlan{
		Fragments: make([]FragmentSpec, 0),
	}

	// 1. Decoy probe with low TTL
	if cfg.UseTTLTrick || cfg.Mode == BypassModeCombinedTtlDecoy {
		probeTTL := cfg.TTLHops
		if probeTTL <= 0 {
			probeTTL = 2
		}
		decoyPayload := fakeHello
		if len(decoyPayload) == 0 {
			decoyPayload = []byte("TLS_DECOY_PROBE")
		}
		plan.DecoyProbe = &DecoyProbeSpec{
			TTL:     probeTTL,
			Payload: decoyPayload,
		}
	}

	// 2. Fragment real ClientHello
	var rawFragments [][]byte
	splitPos := len(realHello) / 2
	if splitPos == 0 {
		splitPos = 1
	}

	// If SNI split is requested, try to find SNI extension boundary
	if cfg.FragmentStrategy == "sni_split" && len(realHello) > 43 {
		// Minimum ClientHello header: 5 (record) + 4 (handshake) + 2 (version) + 32 (random) = 43
		// Attempt split near byte 43 to separate SNI extension from header
		if len(realHello) > 50 {
			splitPos = 43
		}
	}

	if len(realHello) > 1 && splitPos < len(realHello) {
		rawFragments = [][]byte{
			realHello[:splitPos],
			realHello[splitPos:],
		}
	} else {
		rawFragments = [][]byte{realHello}
	}

	for i, frag := range rawFragments {
		delay := 0
		if i > 0 {
			delay = cfg.FragmentDelayMs
		}
		plan.Fragments = append(plan.Fragments, FragmentSpec{
			Payload: frag,
			DelayMs: delay,
		})
	}

	return plan, nil
}

// DomainEvaluationResult stores the outcome of evaluating a domain against a bypass mode.
type DomainEvaluationResult struct {
	Domain     string        `json:"domain"`
	Mode       BypassMode    `json:"mode"`
	Success    bool          `json:"success"`
	LatencyMs  int64         `json:"latency_ms"`
	HttpStatus int           `json:"http_status,omitempty"`
	Error      string        `json:"error,omitempty"`
	TestedAt   time.Time     `json:"tested_at"`
}

// DomainBypassEvaluator evaluates and selects optimal bypass mode for domains.
type DomainBypassEvaluator struct{}

// SelectOptimalMode selects the best bypass mode in hierarchy:
// Direct -> SniFragment -> FakeSniDecoy -> CombinedTtlDecoy -> CombinedRawDesync
func (e *DomainBypassEvaluator) SelectOptimalMode(results []DomainEvaluationResult) (BypassMode, bool) {
	hierarchy := []BypassMode{
		BypassModeDirect,
		BypassModeSniFragment,
		BypassModeFakeSniDecoy,
		BypassModeCombinedTtlDecoy,
		BypassModeCombinedRawDesync,
	}

	for _, mode := range hierarchy {
		for _, res := range results {
			if res.Mode == mode && res.Success {
				return mode, true
			}
		}
	}

	return "", false
}

// ReconstructPayload helper reconstructs the full payload from fragments to verify integrity.
func ReconstructPayload(plan *PreparedEvasionPlan) []byte {
	var buf bytes.Buffer
	for _, f := range plan.Fragments {
		buf.Write(f.Payload)
	}
	return buf.Bytes()
}
