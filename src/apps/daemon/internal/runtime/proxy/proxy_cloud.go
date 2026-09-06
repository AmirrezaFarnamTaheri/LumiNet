package proxy

import (
	"context"
	"sync"
	"time"
)

// ProxyCloudNode represents a proxy server node with configuration and latency data.
type ProxyCloudNode struct {
	ID        string `json:"id"`
	Remark    string `json:"remark"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Type      string `json:"type"`
	FullConf  string `json:"full_config"`
	IsProxy   bool   `json:"is_proxy"`
	LatencyMs int64  `json:"latency_ms"`
}

// ProxyCloudManager orchestrates parallel node testing and package-level routing exclusion.
type ProxyCloudManager struct {
	mu            sync.RWMutex
	nodes         []*ProxyCloudNode
	excludedApps  map[string]bool
	latencyTester *NodeLatencyTester
}

// NewProxyCloudManager initializes a new ProxyCloudManager instance.
func NewProxyCloudManager() *ProxyCloudManager {
	return &ProxyCloudManager{
		excludedApps:  make(map[string]bool),
		latencyTester: NewNodeLatencyTester(),
	}
}

// ConfigureNodes updates the list of active proxy nodes.
func (m *ProxyCloudManager) ConfigureNodes(nodes []*ProxyCloudNode) {
	m.mu.Lock()
	m.nodes = nodes
	m.mu.Unlock()
}

// SetExcludedPackages sets the Android package names to be excluded from the proxy tunnel.
func (m *ProxyCloudManager) SetExcludedPackages(packages []string) {
	m.mu.Lock()
	m.excludedApps = make(map[string]bool)
	for _, pkg := range packages {
		m.excludedApps[pkg] = true
	}
	m.mu.Unlock()
}

// IsAppExcluded returns true if the given application package should bypass the proxy.
func (m *ProxyCloudManager) IsAppExcluded(pkgName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.excludedApps[pkgName]
}

// TestNodeLatency runs a latency check against a specific node.
func (m *ProxyCloudManager) TestNodeLatency(ctx context.Context, node *ProxyCloudNode, timeout time.Duration) int64 {
	addr := node.Address
	// Fallback/TCP check
	res := m.latencyTester.PingTCP(ctx, addr, timeout)
	if res.Success {
		return res.Latency.Milliseconds()
	}
	return -1
}

// SelectFastestNode performs parallel latency checks and returns the node with the lowest latency.
func (m *ProxyCloudManager) SelectFastestNode(ctx context.Context, timeout time.Duration) *ProxyCloudNode {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.nodes) == 0 {
		return nil
	}

	type result struct {
		node    *ProxyCloudNode
		latency int64
	}

	ch := make(chan result, len(m.nodes))
	var wg sync.WaitGroup

	for _, node := range m.nodes {
		wg.Add(1)
		go func(n *ProxyCloudNode) {
			defer wg.Done()
			lat := m.TestNodeLatency(ctx, n, timeout)
			ch <- result{node: n, latency: lat}
		}(node)
	}

	// Close channel when all goroutines finish
	go func() {
		wg.Wait()
		close(ch)
	}()

	var bestNode *ProxyCloudNode
	var lowestLatency int64 = -1

	for res := range ch {
		if res.latency >= 0 {
			if lowestLatency == -1 || res.latency < lowestLatency {
				lowestLatency = res.latency
				bestNode = res.node
			}
		}
	}

	return bestNode
}
