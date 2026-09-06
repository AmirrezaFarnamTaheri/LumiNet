package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const maxStegoSchemeCandidates = 32

type StegoSchemeCandidate struct {
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	Usable         bool   `json:"usable"`
	CapacityBytes  int    `json:"capacity_bytes"`
	RecentFailures int    `json:"recent_failures,omitempty"`
}

type StegoSchemePlanRequest struct {
	Direction    string                 `json:"direction"`
	PayloadBytes int                    `json:"payload_bytes"`
	SelectionKey string                 `json:"selection_key,omitempty"`
	Candidates   []StegoSchemeCandidate `json:"candidates"`
}

type StegoSchemeDecision struct {
	Name          string `json:"name"`
	CapacityBytes int    `json:"capacity_bytes"`
	ExcessBytes   int    `json:"excess_bytes"`
	RankHash      string `json:"rank_hash"`
}

type StegoSchemePlan struct {
	Direction          string                `json:"direction"`
	PayloadBytes       int                   `json:"payload_bytes"`
	Selected           *StegoSchemeDecision  `json:"selected,omitempty"`
	FallbackOrder      []StegoSchemeDecision `json:"fallback_order"`
	Rejected           map[string]string     `json:"rejected"`
	EmbedsPayload      bool                  `json:"embeds_payload"`
	LoadsCoverAssets   bool                  `json:"loads_cover_assets"`
	PerformsNetworkIO  bool                  `json:"performs_network_io"`
	MutatesSchemeState bool                  `json:"mutates_scheme_state"`
	Invariants         []string              `json:"invariants"`
}

var stegSchemeNames = map[string]bool{
	"cookie-transmit": true, "uri-transmit": true, "json-post": true, "pdf-post": true, "jpeg-post": true, "raw-post": true,
	"swf-get": true, "pdf-get": true, "js-get": true, "html-get": true, "json-get": true, "jpeg-get": true, "raw-get": true,
}

func BuildStegoSchemePlan(req StegoSchemePlanRequest) (StegoSchemePlan, error) {
	direction := strings.ToLower(strings.TrimSpace(req.Direction))
	if direction != "client" && direction != "server" {
		return StegoSchemePlan{}, fmt.Errorf("direction must be client or server")
	}
	if req.PayloadBytes < 0 || req.PayloadBytes > 16<<20 {
		return StegoSchemePlan{}, fmt.Errorf("payload_bytes must be 0..16777216")
	}
	if len(req.Candidates) == 0 || len(req.Candidates) > maxStegoSchemeCandidates {
		return StegoSchemePlan{}, fmt.Errorf("candidate count must be 1..%d", maxStegoSchemeCandidates)
	}
	key := strings.TrimSpace(req.SelectionKey)
	if len(key) > 128 {
		return StegoSchemePlan{}, fmt.Errorf("selection_key exceeds 128 bytes")
	}
	if key == "" {
		key = "luminet-stego-selection"
	}
	seen := map[string]bool{}
	rejected := map[string]string{}
	type ranked struct {
		name     string
		cap      int
		excess   int
		sum      [32]byte
		priority int
	}
	eligible := []ranked{}
	for i, raw := range req.Candidates {
		name := strings.ToLower(strings.TrimSpace(raw.Name))
		if !stegSchemeNames[name] {
			return StegoSchemePlan{}, fmt.Errorf("candidate %d has unsupported scheme %q", i, raw.Name)
		}
		if seen[name] {
			return StegoSchemePlan{}, fmt.Errorf("duplicate scheme %q", name)
		}
		seen[name] = true
		if raw.CapacityBytes < 0 || raw.CapacityBytes > 64<<20 {
			return StegoSchemePlan{}, fmt.Errorf("scheme %q capacity is out of bound", name)
		}
		if raw.RecentFailures < 0 || raw.RecentFailures > 1000 {
			return StegoSchemePlan{}, fmt.Errorf("scheme %q recent_failures is out of bound", name)
		}
		reason := ""
		switch {
		case !raw.Enabled:
			reason = "disabled"
		case !raw.Usable:
			reason = "not-usable"
		case raw.CapacityBytes < req.PayloadBytes:
			reason = "insufficient-capacity"
		case raw.RecentFailures >= 3:
			reason = "failure-threshold"
		}
		if reason != "" {
			rejected[name] = reason
			continue
		}
		priority := 2
		if direction == "client" && name == "uri-transmit" && req.PayloadBytes < 300 {
			priority = 0
		} else if direction == "client" && name == "cookie-transmit" && req.PayloadBytes < 700 {
			priority = 1
		}
		sum := sha256.Sum256([]byte(key + "\x00" + name))
		eligible = append(eligible, ranked{name: name, cap: raw.CapacityBytes, excess: raw.CapacityBytes - req.PayloadBytes, sum: sum, priority: priority})
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].priority != eligible[j].priority {
			return eligible[i].priority < eligible[j].priority
		}
		if eligible[i].excess != eligible[j].excess {
			return eligible[i].excess < eligible[j].excess
		}
		a, b := hex.EncodeToString(eligible[i].sum[:]), hex.EncodeToString(eligible[j].sum[:])
		if a != b {
			return a < b
		}
		return eligible[i].name < eligible[j].name
	})
	plan := StegoSchemePlan{
		Direction: direction, PayloadBytes: req.PayloadBytes, Rejected: rejected,
		EmbedsPayload: false, LoadsCoverAssets: false, PerformsNetworkIO: false, MutatesSchemeState: false,
		Invariants: []string{
			"scheme enablement, usability, capacity, and recent failure evidence are evaluated before selection",
			"a cover scheme is never selected when its caller-supplied capacity is smaller than the payload",
			"client payloads below 300 bytes prefer URI transport and payloads below 700 bytes prefer cookie transport when eligible",
			"three or more recent failures quarantine a scheme from the current selection pass",
			"fallback ordering is deterministic and capacity-aware instead of inheriting donor random choice as authority",
			"the planner never loads cover images/PDFs, embeds data, changes scheme success state, or transmits traffic",
		},
	}
	for _, r := range eligible {
		decision := StegoSchemeDecision{Name: r.name, CapacityBytes: r.cap, ExcessBytes: r.excess, RankHash: hex.EncodeToString(r.sum[:])}
		plan.FallbackOrder = append(plan.FallbackOrder, decision)
	}
	if len(plan.FallbackOrder) > 0 {
		selected := plan.FallbackOrder[0]
		plan.Selected = &selected
	}
	return plan, nil
}
