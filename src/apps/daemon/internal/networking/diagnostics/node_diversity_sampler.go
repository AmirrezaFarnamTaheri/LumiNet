package diagnostics

import (
	"math"
	"sort"
	"sync"
)

// DiversityNode holds relay node topology descriptors
type DiversityNode struct {
	NodeID      string
	ASN         uint32
	CountryCode string
	IPPrefix24  string
	LatencyMs   int
}

// DiversityMetrics contains aggregate diversity calculations
type DiversityMetrics struct {
	TotalNodes      int
	UniqueASNs      int
	UniqueCountries int
	AsnEntropy      float64
	DiversityScore  float64
}

// NodeDiversitySampler evaluates topology spread and selects diverse relay sub-clusters
type NodeDiversitySampler struct {
	nodes map[string]DiversityNode
	mu    sync.RWMutex
}

// NewNodeDiversitySampler creates a diversity sampler
func NewNodeDiversitySampler() *NodeDiversitySampler {
	return &NodeDiversitySampler{
		nodes: make(map[string]DiversityNode),
	}
}

// AddNode registers a node
func (s *NodeDiversitySampler) AddNode(node DiversityNode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[node.NodeID] = node
}

// ComputeDiversityMetrics computes ASN entropy and country spread
func (s *NodeDiversitySampler) ComputeDiversityMetrics() DiversityMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.nodes) == 0 {
		return DiversityMetrics{}
	}

	asnCounts := make(map[uint32]int)
	countryCounts := make(map[string]int)

	for _, n := range s.nodes {
		asnCounts[n.ASN]++
		countryCounts[n.CountryCode]++
	}

	total := float64(len(s.nodes))
	entropy := 0.0
	for _, count := range asnCounts {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}

	maxEntropy := math.Log2(total)
	if maxEntropy < 1.0 {
		maxEntropy = 1.0
	}
	normalizedEntropy := math.Min(1.0, entropy/maxEntropy)
	countryFactor := math.Min(1.0, float64(len(countryCounts))/total)
	diversityScore := math.Min(100.0, normalizedEntropy*60.0+countryFactor*40.0)

	return DiversityMetrics{
		TotalNodes:      len(s.nodes),
		UniqueASNs:      len(asnCounts),
		UniqueCountries: len(countryCounts),
		AsnEntropy:      entropy,
		DiversityScore:  diversityScore,
	}
}

// SampleDiverseSubset samples up to maxNodes prioritizing distinct ASNs and lowest latency
func (s *NodeDiversitySampler) SampleDiverseSubset(maxNodes int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []DiversityNode
	for _, n := range s.nodes {
		list = append(list, n)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].LatencyMs < list[j].LatencyMs
	})

	asnSeen := make(map[uint32]bool)
	var sampled []string

	// Pass 1: One per ASN
	for _, n := range list {
		if len(sampled) >= maxNodes {
			break
		}
		if !asnSeen[n.ASN] {
			asnSeen[n.ASN] = true
			sampled = append(sampled, n.NodeID)
		}
	}

	// Pass 2: Fill remaining by lowest latency
	for _, n := range list {
		if len(sampled) >= maxNodes {
			break
		}
		alreadyAdded := false
		for _, id := range sampled {
			if id == n.NodeID {
				alreadyAdded = true
				break
			}
		}
		if !alreadyAdded {
			sampled = append(sampled, n.NodeID)
		}
	}

	return sampled
}
