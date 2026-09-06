package transport

import (
	"math"
	"sort"
	"sync"
)

type EdgeIPRecord struct {
	IPAddress       string
	LatencyMs       uint32
	PacketLossRatio float32
	IsAvailable     bool
}

type EdgeCdnPoolSorter struct {
	mu                   sync.RWMutex
	ipPool               map[string]EdgeIPRecord
	maxLatencyThreshold  uint32
}

func NewEdgeCdnPoolSorter(maxLatencyThreshold uint32) *EdgeCdnPoolSorter {
	return &EdgeCdnPoolSorter{
		ipPool:              make(map[string]EdgeIPRecord),
		maxLatencyThreshold: maxLatencyThreshold,
	}
}

func (s *EdgeCdnPoolSorter) AddIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipPool[ip] = EdgeIPRecord{
		IPAddress:       ip,
		LatencyMs:       math.MaxUint32,
		PacketLossRatio: 1.0,
		IsAvailable:     false,
	}
}

func (s *EdgeCdnPoolSorter) UpdateProbeResult(ip string, latencyMs uint32, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.ipPool[ip]
	if !exists {
		return
	}

	if success {
		entry.LatencyMs = latencyMs
		entry.PacketLossRatio = 0.0
		entry.IsAvailable = latencyMs <= s.maxLatencyThreshold
	} else {
		entry.PacketLossRatio = 1.0
		entry.IsAvailable = false
	}
	s.ipPool[ip] = entry
}

func (s *EdgeCdnPoolSorter) GetSortedFastest() []EdgeIPRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var available []EdgeIPRecord
	for _, r := range s.ipPool {
		if r.IsAvailable {
			available = append(available, r)
		}
	}

	sort.Slice(available, func(i, j int) bool {
		return available[i].LatencyMs < available[j].LatencyMs
	})

	return available
}

func (s *EdgeCdnPoolSorter) BestIP() (string, bool) {
	fastest := s.GetSortedFastest()
	if len(fastest) == 0 {
		return "", false
	}
	return fastest[0].IPAddress, true
}
