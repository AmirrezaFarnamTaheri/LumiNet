package proxyconfig

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// PublicRelayNode holds metadata for a community proxy or VPN relay
type PublicRelayNode struct {
	NodeID      string    `json:"node_id"`
	Protocol    string    `json:"protocol"` // e.g. "shadowsocks", "vless", "wireguard", "openvpn"
	Host        string    `json:"host"`
	Port        uint16    `json:"port"`
	CountryCode string    `json:"country_code"`
	PingMs      int       `json:"ping_ms"`
	UptimeRatio float64   `json:"uptime_ratio"` // 0.0 to 1.0
	LastSeen    time.Time `json:"last_seen"`
	IsAlive     bool      `json:"is_alive"`
}

// PublicRelayAggregator indexes, filters, and ranks public relay servers
type PublicRelayAggregator struct {
	relays map[string]PublicRelayNode // keyed by NodeID
	mu     sync.RWMutex
}

// NewPublicRelayAggregator creates an aggregator instance
func NewPublicRelayAggregator() *PublicRelayAggregator {
	return &PublicRelayAggregator{
		relays: make(map[string]PublicRelayNode),
	}
}

// IngestNode registers or updates a public relay
func (a *PublicRelayAggregator) IngestNode(node PublicRelayNode) error {
	if node.NodeID == "" || node.Host == "" || node.Port == 0 {
		return errors.New("invalid node descriptor")
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	node.LastSeen = time.Now()
	a.relays[node.NodeID] = node
	return nil
}

// UpdateHealth updates latency and alive state of a relay
func (a *PublicRelayAggregator) UpdateHealth(nodeID string, pingMs int, isAlive bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	node, exists := a.relays[nodeID]
	if !exists {
		return false
	}
	node.PingMs = pingMs
	node.IsAlive = isAlive
	node.LastSeen = time.Now()
	a.relays[nodeID] = node
	return true
}

// QueryRelays filters relays by country and protocol, sorted by latency
func (a *PublicRelayAggregator) QueryRelays(country string, proto string, maxResults int) []PublicRelayNode {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var matched []PublicRelayNode
	for _, n := range a.relays {
		if !n.IsAlive {
			continue
		}
		if country != "" && n.CountryCode != country {
			continue
		}
		if proto != "" && n.Protocol != proto {
			continue
		}
		matched = append(matched, n)
	}

	// Sort by PingMs ascending
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].PingMs < matched[j].PingMs
	})

	if maxResults > 0 && len(matched) > maxResults {
		matched = matched[:maxResults]
	}
	return matched
}

// TotalCount returns count of registered relays
func (a *PublicRelayAggregator) TotalCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.relays)
}
