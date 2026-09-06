package proxyconfig

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// UpstreamNode defines an outbound node in the multi-protocol matrix.
type UpstreamNode struct {
	ID       string        `json:"id"`
	Protocol string        `json:"protocol"`
	Endpoint string        `json:"endpoint"`
	Weight   int           `json:"weight"`
	Latency  time.Duration `json:"latency"`
	IsAlive  bool          `json:"is_alive"`
}

// UpstreamMatrix manages pool of heterogeneous proxy upstreams.
type UpstreamMatrix struct {
	mu    sync.Mutex
	nodes map[string]*UpstreamNode
}

// NewUpstreamMatrix initializes a matrix.
func NewUpstreamMatrix() *UpstreamMatrix {
	return &UpstreamMatrix{
		nodes: make(map[string]*UpstreamNode),
	}
}

// RegisterNode adds or updates a node in the matrix.
func (m *UpstreamMatrix) RegisterNode(node UpstreamNode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes[node.ID] = &node
}

// UpdateHealth updates health status and latency for an upstream.
func (m *UpstreamMatrix) UpdateHealth(id string, isAlive bool, latency time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	node, exists := m.nodes[id]
	if !exists {
		return fmt.Errorf("node not found: %s", id)
	}

	node.IsAlive = isAlive
	node.Latency = latency
	return nil
}

// SelectBestNode returns the healthy node with lowest latency, factoring weight.
func (m *UpstreamMatrix) SelectBestNode() (*UpstreamNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var healthy []*UpstreamNode
	for _, n := range m.nodes {
		if n.IsAlive {
			healthy = append(healthy, n)
		}
	}

	if len(healthy) == 0 {
		return nil, fmt.Errorf("no healthy upstreams available")
	}

	sort.Slice(healthy, func(i, j int) bool {
		// Prefer lower latency
		return healthy[i].Latency < healthy[j].Latency
	})

	return healthy[0], nil
}
