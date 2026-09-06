package diagnostics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/maybeknott/luminet/internal/foundation/netpolicy"
)

const maxPhantomCandidates = 1024

type PhantomPoolCandidate struct {
	ID            string `json:"id"`
	Address       string `json:"address"`
	Transport     string `json:"transport,omitempty"`
	Liveness      string `json:"liveness"`
	CheckedAtUnix int64  `json:"checked_at_unix,omitempty"`
	Weight        int    `json:"weight,omitempty"`
}

type PhantomPoolRequest struct {
	Candidates    []PhantomPoolCandidate `json:"candidates"`
	SelectionKey  string                 `json:"selection_key,omitempty"`
	Transport     string                 `json:"transport,omitempty"`
	NowUnix       int64                  `json:"now_unix"`
	MaxAgeSeconds int64                  `json:"max_age_seconds,omitempty"`
	Count         int                    `json:"count,omitempty"`
}

type PhantomPoolDecision struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	Transport string `json:"transport"`
	RankHash  string `json:"rank_hash"`
}
type PhantomPoolPlan struct {
	Selected              []PhantomPoolDecision `json:"selected"`
	Rejected              map[string]string     `json:"rejected"`
	PerformsLivenessProbe bool                  `json:"performs_liveness_probe"`
	RegistersPhantom      bool                  `json:"registers_phantom"`
	PerformsNetworkIO     bool                  `json:"performs_network_io"`
	ReadOnly              bool                  `json:"read_only"`
	Invariants            []string              `json:"invariants"`
}

func BuildPhantomPoolPlan(req PhantomPoolRequest) (PhantomPoolPlan, error) {
	if len(req.Candidates) == 0 || len(req.Candidates) > maxPhantomCandidates {
		return PhantomPoolPlan{}, fmt.Errorf("phantom candidate count must be 1..%d", maxPhantomCandidates)
	}
	if req.NowUnix <= 0 {
		return PhantomPoolPlan{}, fmt.Errorf("now_unix must be positive")
	}
	maxAge := req.MaxAgeSeconds
	if maxAge == 0 {
		maxAge = 300
	}
	if maxAge < 1 || maxAge > 86400 {
		return PhantomPoolPlan{}, fmt.Errorf("max_age_seconds must be 1..86400")
	}
	count := req.Count
	if count == 0 {
		count = 1
	}
	if count < 1 || count > 16 {
		return PhantomPoolPlan{}, fmt.Errorf("count must be 1..16")
	}
	key := strings.TrimSpace(req.SelectionKey)
	if len(key) > 128 {
		return PhantomPoolPlan{}, fmt.Errorf("selection_key exceeds 128 bytes")
	}
	if key == "" {
		key = "luminet-phantom-pool"
	}
	wantTransport := strings.ToLower(strings.TrimSpace(req.Transport))
	rejected := map[string]string{}
	seen := map[string]bool{}
	type rank struct {
		c   PhantomPoolCandidate
		sum [32]byte
	}
	ranks := []rank{}
	for _, raw := range req.Candidates {
		c := raw
		c.ID = strings.TrimSpace(c.ID)
		c.Address = strings.TrimSpace(c.Address)
		c.Transport = strings.ToLower(strings.TrimSpace(c.Transport))
		c.Liveness = strings.ToLower(strings.TrimSpace(c.Liveness))
		if c.ID == "" || len(c.ID) > 128 || seen[c.ID] {
			return PhantomPoolPlan{}, fmt.Errorf("invalid or duplicate phantom id %q", c.ID)
		}
		seen[c.ID] = true
		addr, err := netip.ParseAddr(c.Address)
		if err != nil || !netpolicy.IsPublicAddress(addr) {
			rejected[c.ID] = "non-public-address"
			continue
		}
		if c.Liveness != "not-live" && c.Liveness != "live" && c.Liveness != "unknown" {
			return PhantomPoolPlan{}, fmt.Errorf("phantom %q has invalid liveness", c.ID)
		}
		if c.Liveness != "not-live" {
			rejected[c.ID] = "liveness-not-confirmed-free"
			continue
		}
		if c.CheckedAtUnix <= 0 || c.CheckedAtUnix > req.NowUnix || req.NowUnix-c.CheckedAtUnix > maxAge {
			rejected[c.ID] = "stale-liveness-evidence"
			continue
		}
		if wantTransport != "" && c.Transport != wantTransport {
			rejected[c.ID] = "transport-mismatch"
			continue
		}
		if c.Weight == 0 {
			c.Weight = 1
		}
		if c.Weight < 1 || c.Weight > 1000 {
			return PhantomPoolPlan{}, fmt.Errorf("phantom %q weight must be 1..1000", c.ID)
		}
		// Mix the weight into the deterministic rank by adding replicated virtual-rank choices and retaining the minimum.
		best := sha256.Sum256([]byte(key + "\x00" + c.ID + "\x000"))
		virtual := c.Weight
		if virtual > 64 {
			virtual = 64
		}
		for i := 1; i < virtual; i++ {
			s := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", key, c.ID, i)))
			if strings.Compare(hex.EncodeToString(s[:]), hex.EncodeToString(best[:])) < 0 {
				best = s
			}
		}
		ranks = append(ranks, rank{c: c, sum: best})
	}
	sort.Slice(ranks, func(i, j int) bool {
		a := hex.EncodeToString(ranks[i].sum[:])
		b := hex.EncodeToString(ranks[j].sum[:])
		if a == b {
			return ranks[i].c.ID < ranks[j].c.ID
		}
		return a < b
	})
	if count > len(ranks) {
		count = len(ranks)
	}
	selected := make([]PhantomPoolDecision, 0, count)
	for i := 0; i < count; i++ {
		r := ranks[i]
		selected = append(selected, PhantomPoolDecision{ID: r.c.ID, Address: r.c.Address, Transport: r.c.Transport, RankHash: hex.EncodeToString(r.sum[:])})
	}
	return PhantomPoolPlan{Selected: selected, Rejected: rejected, PerformsLivenessProbe: false, RegistersPhantom: false, PerformsNetworkIO: false, ReadOnly: true, Invariants: []string{
		"only public endpoints with fresh caller-supplied not-live evidence are eligible",
		"live, unknown, stale, future-dated, and transport-incompatible candidates are excluded before ranking",
		"weighted deterministic ranking is bounded and never expands donor subnets or contacts a registration service",
		"the planner neither probes liveness nor registers or activates a phantom endpoint",
	}}, nil
}
