package diagnostics

import (
	"sort"
	"sync"
)

type DohEndpoint struct {
	URL                 string
	Host                string
	Tier                int
	IsHealthy           bool
	ConsecutiveFailures int
	AvgLatencyMs        int
}

type DohFallbackHierarchy struct {
	mu        sync.RWMutex
	endpoints map[string]*DohEndpoint
}

func NewDohFallbackHierarchy() *DohFallbackHierarchy {
	h := &DohFallbackHierarchy{
		endpoints: make(map[string]*DohEndpoint),
	}
	h.RegisterDefaults()
	return h
}

func (h *DohFallbackHierarchy) RegisterDefaults() {
	h.AddEndpoint(&DohEndpoint{
		URL:          "https://1.1.1.1/dns-query",
		Host:         "cloudflare-dns.com",
		Tier:         1,
		IsHealthy:    true,
		AvgLatencyMs: 25,
	})
	h.AddEndpoint(&DohEndpoint{
		URL:          "https://dns.google/dns-query",
		Host:         "dns.google",
		Tier:         1,
		IsHealthy:    true,
		AvgLatencyMs: 35,
	})
	h.AddEndpoint(&DohEndpoint{
		URL:          "https://doh.opendns.com/dns-query",
		Host:         "doh.opendns.com",
		Tier:         2,
		IsHealthy:    true,
		AvgLatencyMs: 60,
	})
}

func (h *DohFallbackHierarchy) AddEndpoint(ep *DohEndpoint) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.endpoints[ep.URL] = ep
}

func (h *DohFallbackHierarchy) RecordFailure(url string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ep, ok := h.endpoints[url]; ok {
		ep.ConsecutiveFailures++
		if ep.ConsecutiveFailures >= 3 {
			ep.IsHealthy = false
		}
	}
}

func (h *DohFallbackHierarchy) SelectActive() *DohEndpoint {
	h.mu.RLock()
	defer h.mu.RUnlock()

	candidates := make([]*DohEndpoint, 0)
	for _, ep := range h.endpoints {
		if ep.IsHealthy {
			candidates = append(candidates, ep)
		}
	}
	if len(candidates) == 0 {
		for _, ep := range h.endpoints {
			return ep
		}
		return nil
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Tier != candidates[j].Tier {
			return candidates[i].Tier < candidates[j].Tier
		}
		return candidates[i].AvgLatencyMs < candidates[j].AvgLatencyMs
	})

	return candidates[0]
}
