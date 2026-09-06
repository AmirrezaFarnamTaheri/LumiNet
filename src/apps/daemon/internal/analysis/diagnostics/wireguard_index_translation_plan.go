package diagnostics

import (
	"fmt"
	"strings"
	"time"
)

type WireGuardIndexTranslationEntry struct {
	SourceReceiverIndex     uint32    `json:"source_receiver_index"`
	TranslatedReceiverIndex uint32    `json:"translated_receiver_index"`
	PeerIdentity            string    `json:"peer_identity"`
	ExpiresAt               time.Time `json:"expires_at"`
	Persisted               bool      `json:"persisted,omitempty"`
}

type WireGuardIndexTranslationRequest struct {
	Entries []WireGuardIndexTranslationEntry `json:"entries"`
	AsOf    time.Time                        `json:"as_of,omitempty"`
}

type WireGuardIndexTranslationPlan struct {
	Entries                    []WireGuardIndexTranslationEntry `json:"entries"`
	PersistedNeedsRevalidation []uint32                         `json:"persisted_needs_revalidation"`
	MACRecomputeRequired       bool                             `json:"mac_recompute_required"`
	MutatesPackets             bool                             `json:"mutates_packets"`
	RestoresMappings           bool                             `json:"restores_mappings"`
	ReadOnly                   bool                             `json:"read_only"`
	Invariants                 []string                         `json:"invariants"`
}

// BuildWireGuardIndexTranslationPlan captures the safe contract implied by an
// index-rewriting relay without becoming a packet mutator. Persisted mappings
// are never trusted after restart until identity and expiry are revalidated.
func BuildWireGuardIndexTranslationPlan(req WireGuardIndexTranslationRequest) (WireGuardIndexTranslationPlan, error) {
	if len(req.Entries) == 0 || len(req.Entries) > 1024 {
		return WireGuardIndexTranslationPlan{}, fmt.Errorf("WireGuard index translation entry count must be 1..1024")
	}
	asOf := req.AsOf
	if asOf.IsZero() {
		asOf = time.Now().UTC()
	}
	seenSource := map[uint32]bool{}
	seenTranslated := map[uint32]bool{}
	plan := WireGuardIndexTranslationPlan{
		Entries:              append([]WireGuardIndexTranslationEntry(nil), req.Entries...),
		MACRecomputeRequired: true,
		ReadOnly:             true,
		Invariants: []string{
			"source and translated receiver indexes are nonzero and unique within the plan",
			"every translation is bound to an explicit peer identity and a future expiry no more than 24 hours away",
			"persisted mappings are recovery hints only and require identity and expiry revalidation after restart",
			"any live receiver-index rewrite must recompute the affected WireGuard packet authentication fields before transmission",
			"index translation never substitutes for WireGuard key agreement, replay protection, cookie/MAC2 admission, or peer authentication",
			"this planner rewrites no packet and restores no mapping into a live WireGuard owner",
		},
	}
	for i, entry := range req.Entries {
		if entry.SourceReceiverIndex == 0 || seenSource[entry.SourceReceiverIndex] {
			return WireGuardIndexTranslationPlan{}, fmt.Errorf("WireGuard translation entry %d has invalid or duplicate source receiver index", i)
		}
		if entry.TranslatedReceiverIndex == 0 || seenTranslated[entry.TranslatedReceiverIndex] {
			return WireGuardIndexTranslationPlan{}, fmt.Errorf("WireGuard translation entry %d has invalid or duplicate translated receiver index", i)
		}
		identity := strings.TrimSpace(entry.PeerIdentity)
		if identity == "" || len(identity) > 256 {
			return WireGuardIndexTranslationPlan{}, fmt.Errorf("WireGuard translation entry %d requires bounded peer identity", i)
		}
		if entry.ExpiresAt.IsZero() || !entry.ExpiresAt.After(asOf) || entry.ExpiresAt.Sub(asOf) > 24*time.Hour {
			return WireGuardIndexTranslationPlan{}, fmt.Errorf("WireGuard translation entry %d requires future expiry within 24 hours", i)
		}
		seenSource[entry.SourceReceiverIndex] = true
		seenTranslated[entry.TranslatedReceiverIndex] = true
		plan.Entries[i].PeerIdentity = identity
		if entry.Persisted {
			plan.PersistedNeedsRevalidation = append(plan.PersistedNeedsRevalidation, entry.SourceReceiverIndex)
		}
	}
	return plan, nil
}
