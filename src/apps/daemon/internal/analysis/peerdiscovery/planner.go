package peerdiscovery

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/maybeknott/luminet/internal/foundation/netpolicy"
)

const (
	MaxCandidates   = 1000
	MaxResults      = 64
	MaxBlockedCIDRs = 128
)

type Candidate struct {
	NodeID  string `json:"node_id"`
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

type PlanRequest struct {
	LocalNodeID  string      `json:"local_node_id"`
	Candidates   []Candidate `json:"candidates"`
	BlockedCIDRs []string    `json:"blocked_cidrs,omitempty"`
	MaxResults   int         `json:"max_results,omitempty"`
}

type PlannedPeer struct {
	NodeID                string  `json:"node_id"`
	Address               string  `json:"address"`
	Port                  uint16  `json:"port"`
	Distance              string  `json:"distance"`
	TrustObserved         bool    `json:"trust_observed"`
	TrustScore            float64 `json:"trust_score,omitempty"`
	SharedAddressObserved bool    `json:"shared_address_observed"`
	SharedAddressCount    int     `json:"shared_address_count,omitempty"`
}

type RejectedPeer struct {
	NodeID  string `json:"node_id,omitempty"`
	Address string `json:"address,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	Reason  string `json:"reason"`
	Detail  string `json:"detail"`
}

type Plan struct {
	LocalNodeID        string         `json:"local_node_id"`
	Accepted           []PlannedPeer  `json:"accepted"`
	Rejected           []RejectedPeer `json:"rejected"`
	EligibleCount      int            `json:"eligible_count"`
	ReturnedCount      int            `json:"returned_count"`
	RejectedCount      int            `json:"rejected_count"`
	BlockedPrefixCount int            `json:"blocked_prefix_count"`
	MaxResults         int            `json:"max_results"`
	SelectionModel     string         `json:"selection_model"`
	IdentityModel      string         `json:"identity_model"`
	SafetyBoundary     string         `json:"safety_boundary"`
}

// BuildPlan validates a bounded operator-supplied peer set and returns the
// closest admitted peers by exact 160-bit XOR distance. observedTrust is
// optional descriptive runtime evidence keyed by normalized node ID; it does
// not make a peer admissible and does not change distance ordering.
func BuildPlan(req PlanRequest, observedTrust map[string]float64) (Plan, error) {
	localID, err := ParseNodeID(req.LocalNodeID)
	if err != nil {
		return Plan{}, fmt.Errorf("invalid local_node_id: %w", err)
	}
	if len(req.Candidates) == 0 || len(req.Candidates) > MaxCandidates {
		return Plan{}, fmt.Errorf("candidate count must be between 1 and %d", MaxCandidates)
	}
	limit := req.MaxResults
	if limit == 0 {
		limit = 20
	}
	if limit < 1 || limit > MaxResults {
		return Plan{}, fmt.Errorf("max_results must be between 1 and %d", MaxResults)
	}
	blockedPrefixes, err := parseBlockedCIDRs(req.BlockedCIDRs)
	if err != nil {
		return Plan{}, err
	}

	seenIDs := make(map[string]struct{}, len(req.Candidates))
	seenEndpoints := make(map[string]struct{}, len(req.Candidates))
	accepted := make([]PlannedPeer, 0, len(req.Candidates))
	rejected := make([]RejectedPeer, 0)

	for _, candidate := range req.Candidates {
		normalizedID := strings.ToLower(strings.TrimSpace(candidate.NodeID))
		normalizedAddress := strings.TrimSpace(candidate.Address)
		reject := func(reason, detail string) {
			rejected = append(rejected, RejectedPeer{
				NodeID: normalizedID, Address: normalizedAddress, Port: candidate.Port,
				Reason: reason, Detail: detail,
			})
		}

		id, parseErr := ParseNodeID(normalizedID)
		if parseErr != nil {
			reject("invalid-node-id", parseErr.Error())
			continue
		}
		if id == localID {
			reject("self", "candidate node ID equals local node ID")
			continue
		}
		if _, exists := seenIDs[normalizedID]; exists {
			reject("duplicate-node-id", "node ID already appeared in the admitted candidate set")
			continue
		}

		address, parseErr := netip.ParseAddr(normalizedAddress)
		if parseErr != nil {
			reject("invalid-address", "address must be a literal IPv4 address")
			continue
		}
		address = address.Unmap()
		if !address.Is4() {
			reject("unsupported-address-family", "this BEP42 admission plane currently accepts IPv4 only")
			continue
		}
		if !netpolicy.IsPublicAddress(address) {
			reject("non-public-address", "peer address is outside LumiNet public-endpoint admission policy")
			continue
		}
		if prefixContains(blockedPrefixes, address) {
			reject("blocked-address", "peer address matches an operator-supplied local deny prefix")
			continue
		}
		if candidate.Port == 0 {
			reject("invalid-port", "peer port must be between 1 and 65535")
			continue
		}
		endpointKey := fmt.Sprintf("%s:%d", address, candidate.Port)
		if _, exists := seenEndpoints[endpointKey]; exists {
			reject("duplicate-endpoint", "address and port already appeared in the admitted candidate set")
			continue
		}
		if !ValidIPv4NodeID(id, address) {
			reject("bep42-mismatch", "node ID prefix is not bound to the advertised IPv4 address")
			continue
		}
		// Invalid candidates must not reserve a node ID or endpoint and suppress
		// a later valid observation in the same operator-supplied batch.
		seenIDs[normalizedID] = struct{}{}
		seenEndpoints[endpointKey] = struct{}{}

		distance := xorDistance(localID, id)
		planned := PlannedPeer{
			NodeID:   normalizedID,
			Address:  address.String(),
			Port:     candidate.Port,
			Distance: hex.EncodeToString(distance[:]),
		}
		if score, ok := observedTrust[normalizedID]; ok {
			planned.TrustObserved = true
			planned.TrustScore = clamp01(score)
		}
		accepted = append(accepted, planned)
	}

	// Multiple valid peers behind one public address can be legitimate (for
	// example, NAT with different listening ports), so address reuse is
	// surfaced as descriptive evidence rather than treated as an identity
	// failure. Operators can combine this evidence with trust and local policy.
	addressCounts := make(map[string]int, len(accepted))
	for _, peer := range accepted {
		addressCounts[peer.Address]++
	}
	for i := range accepted {
		if count := addressCounts[accepted[i].Address]; count > 1 {
			accepted[i].SharedAddressObserved = true
			accepted[i].SharedAddressCount = count
		}
	}

	sort.SliceStable(accepted, func(i, j int) bool {
		if accepted[i].Distance == accepted[j].Distance {
			return accepted[i].NodeID < accepted[j].NodeID
		}
		return accepted[i].Distance < accepted[j].Distance
	})
	eligibleCount := len(accepted)
	if len(accepted) > limit {
		accepted = accepted[:limit]
	}

	return Plan{
		LocalNodeID:        localID.String(),
		Accepted:           accepted,
		Rejected:           rejected,
		EligibleCount:      eligibleCount,
		ReturnedCount:      len(accepted),
		RejectedCount:      len(rejected),
		BlockedPrefixCount: len(blockedPrefixes),
		MaxResults:         limit,
		SelectionModel:     "bep42-admission-then-xor-distance",
		IdentityModel:      "BEP42 IPv4 21-bit IP-bound node-ID prefix",
		SafetyBoundary:     "read-only planner; local CIDR deny policy only; no DNSBL lookups, sockets, peer dialing, persistence, route mutation, or trust-based identity bypass",
	}, nil
}

func parseBlockedCIDRs(raw []string) ([]netip.Prefix, error) {
	if len(raw) > MaxBlockedCIDRs {
		return nil, fmt.Errorf("blocked_cidrs may contain at most %d entries", MaxBlockedCIDRs)
	}
	prefixes := make([]netip.Prefix, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for index, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 64 {
			return nil, fmt.Errorf("blocked_cidrs[%d] must be a non-empty IPv4 CIDR no longer than 64 characters", index)
		}
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("blocked_cidrs[%d] must be a valid IPv4 CIDR", index)
		}
		prefix = prefix.Masked()
		key := prefix.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func prefixContains(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func xorDistance(a, b NodeID) NodeID {
	var out NodeID
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func clamp01(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}
