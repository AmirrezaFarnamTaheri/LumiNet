package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const maxTorBridgeCandidates = 512

type TorBridgeSelectionCandidate struct {
	ID            string   `json:"id"`
	Transport     string   `json:"transport"`
	Address       string   `json:"address"`
	AddressFamily string   `json:"address_family,omitempty"`
	Running       bool     `json:"running"`
	Stable        bool     `json:"stable"`
	BlockedIn     []string `json:"blocked_in,omitempty"`
}

type TorBridgeSelectionRequest struct {
	Candidates    []TorBridgeSelectionCandidate `json:"candidates"`
	Country       string                        `json:"country,omitempty"`
	Transport     string                        `json:"transport,omitempty"`
	AddressFamily string                        `json:"address_family,omitempty"`
	RequireStable bool                          `json:"require_stable,omitempty"`
	Count         int                           `json:"count,omitempty"`
	SelectionKey  string                        `json:"selection_key,omitempty"`
}

type TorBridgeSelectionDecision struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	Transport string `json:"transport"`
	RankHash  string `json:"rank_hash"`
}

type TorBridgeSelectionPlan struct {
	Selected          []TorBridgeSelectionDecision `json:"selected"`
	Eligible          int                          `json:"eligible"`
	Rejected          map[string]string            `json:"rejected"`
	RequestedCount    int                          `json:"requested_count"`
	AdaptiveCount     bool                         `json:"adaptive_count"`
	FetchesBridges    bool                         `json:"fetches_bridges"`
	PersistsClientKey bool                         `json:"persists_client_key"`
	PerformsNetworkIO bool                         `json:"performs_network_io"`
	ReadOnly          bool                         `json:"read_only"`
	Invariants        []string                     `json:"invariants"`
}

func BuildTorBridgeSelectionPlan(req TorBridgeSelectionRequest) (TorBridgeSelectionPlan, error) {
	if len(req.Candidates) == 0 || len(req.Candidates) > maxTorBridgeCandidates {
		return TorBridgeSelectionPlan{}, fmt.Errorf("Tor bridge candidate count must be 1..%d", maxTorBridgeCandidates)
	}
	country := strings.ToLower(strings.TrimSpace(req.Country))
	if len(country) > 2 || (country != "" && len(country) != 2) {
		return TorBridgeSelectionPlan{}, fmt.Errorf("country must be empty or a two-letter code")
	}
	transport := strings.ToLower(strings.TrimSpace(req.Transport))
	family := strings.ToLower(strings.TrimSpace(req.AddressFamily))
	if family != "" && family != "4" && family != "6" {
		return TorBridgeSelectionPlan{}, fmt.Errorf("address_family must be 4 or 6")
	}
	key := strings.TrimSpace(req.SelectionKey)
	if len(key) > 128 {
		return TorBridgeSelectionPlan{}, fmt.Errorf("selection_key exceeds 128 bytes")
	}
	if key == "" {
		key = "luminet-bridge-selection"
	}

	rejected := map[string]string{}
	seen := map[string]bool{}
	eligible := make([]TorBridgeSelectionCandidate, 0, len(req.Candidates))
	for _, raw := range req.Candidates {
		c := raw
		c.ID = strings.TrimSpace(c.ID)
		c.Address = strings.TrimSpace(c.Address)
		c.Transport = strings.ToLower(strings.TrimSpace(c.Transport))
		c.AddressFamily = strings.ToLower(strings.TrimSpace(c.AddressFamily))
		if c.ID == "" || len(c.ID) > 128 || seen[c.ID] {
			return TorBridgeSelectionPlan{}, fmt.Errorf("invalid or duplicate bridge id %q", c.ID)
		}
		seen[c.ID] = true
		if c.Address == "" || len(c.Address) > 512 {
			return TorBridgeSelectionPlan{}, fmt.Errorf("bridge %q has invalid address", c.ID)
		}
		if c.AddressFamily != "" && c.AddressFamily != "4" && c.AddressFamily != "6" {
			return TorBridgeSelectionPlan{}, fmt.Errorf("bridge %q has invalid address family", c.ID)
		}
		reason := ""
		if !c.Running {
			reason = "not-running"
		} else if req.RequireStable && !c.Stable {
			reason = "not-stable"
		} else if transport != "" && c.Transport != transport {
			reason = "transport-mismatch"
		} else if family != "" && c.AddressFamily != family {
			reason = "address-family-mismatch"
		} else if country != "" && containsFold(c.BlockedIn, country) {
			reason = "blocked-in-country"
		}
		if reason != "" {
			rejected[c.ID] = reason
			continue
		}
		eligible = append(eligible, c)
	}

	count := req.Count
	adaptive := false
	if count == 0 {
		adaptive = true
		switch {
		case len(eligible) <= 20:
			count = 1
		case len(eligible) <= 100:
			count = 2
		default:
			count = 3
		}
	}
	if count < 1 || count > 8 {
		return TorBridgeSelectionPlan{}, fmt.Errorf("bridge selection count must be 1..8")
	}
	if count > len(eligible) {
		count = len(eligible)
	}

	type ranked struct {
		c   TorBridgeSelectionCandidate
		sum [32]byte
	}
	ranks := make([]ranked, 0, len(eligible))
	for _, c := range eligible {
		ranks = append(ranks, ranked{c: c, sum: sha256.Sum256([]byte(key + "\x00" + c.ID))})
	}
	sort.Slice(ranks, func(i, j int) bool {
		a, b := hex.EncodeToString(ranks[i].sum[:]), hex.EncodeToString(ranks[j].sum[:])
		if a == b {
			return ranks[i].c.ID < ranks[j].c.ID
		}
		return a < b
	})
	selected := make([]TorBridgeSelectionDecision, 0, count)
	for i := 0; i < count; i++ {
		r := ranks[i]
		selected = append(selected, TorBridgeSelectionDecision{ID: r.c.ID, Address: r.c.Address, Transport: r.c.Transport, RankHash: hex.EncodeToString(r.sum[:])})
	}
	return TorBridgeSelectionPlan{
		Selected: selected, Eligible: len(eligible), Rejected: rejected, RequestedCount: count, AdaptiveCount: adaptive,
		FetchesBridges: false, PersistsClientKey: false, PerformsNetworkIO: false, ReadOnly: true,
		Invariants: []string{
			"selection operates only on caller-supplied bridge evidence and never contacts a distributor",
			"blocked-country, transport, address-family, running, and stability constraints are applied before ranking",
			"ranking is deterministic for a supplied selection key and does not persist that key",
			"adaptive response size is bounded to one through three bridges and explicit requests are capped at eight",
		},
	}, nil
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}
