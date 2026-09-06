package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
)

type PacSyncDelta struct {
	AddedDomains     []string `json:"added_domains"`
	RemovedDomains   []string `json:"removed_domains"`
	PreviousChecksum string   `json:"previous_checksum"`
	NewChecksum      string   `json:"new_checksum"`
}

type PacDiffSynchronizer struct {
	activeRules map[string]struct{}
}

func NewPacDiffSynchronizer(initialRules []string) *PacDiffSynchronizer {
	rules := make(map[string]struct{})
	for _, r := range initialRules {
		trimmed := strings.ToLower(strings.TrimSpace(r))
		if trimmed != "" {
			rules[trimmed] = struct{}{}
		}
	}
	return &PacDiffSynchronizer{activeRules: rules}
}

func (p *PacDiffSynchronizer) ComputeDelta(upstreamRules []string) PacSyncDelta {
	upstreamMap := make(map[string]struct{})
	for _, r := range upstreamRules {
		trimmed := strings.ToLower(strings.TrimSpace(r))
		if trimmed != "" {
			upstreamMap[trimmed] = struct{}{}
		}
	}

	var added []string
	for r := range upstreamMap {
		if _, exists := p.activeRules[r]; !exists {
			added = append(added, r)
		}
	}
	sort.Strings(added)

	var removed []string
	for r := range p.activeRules {
		if _, exists := upstreamMap[r]; !exists {
			removed = append(removed, r)
		}
	}
	sort.Strings(removed)

	return PacSyncDelta{
		AddedDomains:     added,
		RemovedDomains:   removed,
		PreviousChecksum: p.CurrentChecksum(),
		NewChecksum:      p.computeChecksumForSet(upstreamMap),
	}
}

func (p *PacDiffSynchronizer) ApplyDelta(delta PacSyncDelta) (int, error) {
	if p.CurrentChecksum() != delta.PreviousChecksum {
		return 0, errors.New("checksum mismatch: concurrent modification detected")
	}

	for _, rem := range delta.RemovedDomains {
		delete(p.activeRules, rem)
	}
	for _, add := range delta.AddedDomains {
		p.activeRules[add] = struct{}{}
	}

	if p.CurrentChecksum() != delta.NewChecksum {
		return 0, errors.New("post-apply checksum mismatch")
	}

	return len(p.activeRules), nil
}

func (p *PacDiffSynchronizer) CurrentChecksum() string {
	return p.computeChecksumForSet(p.activeRules)
}

func (p *PacDiffSynchronizer) TotalRules() int {
	return len(p.activeRules)
}

func (p *PacDiffSynchronizer) ContainsRule(domain string) bool {
	_, ok := p.activeRules[strings.ToLower(strings.TrimSpace(domain))]
	return ok
}

func (p *PacDiffSynchronizer) computeChecksumForSet(set map[string]struct{}) string {
	var list []string
	for k := range set {
		list = append(list, k)
	}
	sort.Strings(list)

	h := sha256.New()
	for _, item := range list {
		h.Write([]byte(item))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
