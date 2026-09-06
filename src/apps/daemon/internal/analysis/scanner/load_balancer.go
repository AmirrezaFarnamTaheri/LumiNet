
package scanner

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// BalancerNode represents a destination proxy backend with weight metadata.
type BalancerNode struct {
	Address string
	Weight  int32
	Latency int64 // Latency in microseconds
	Active  bool
}

// LoadBalancer routes connections across multiple nodes using weighted round-robin.
type LoadBalancer struct {
	mu      sync.RWMutex
	nodes   []*BalancerNode
	counter uint64
}

// NewLoadBalancer creates a new proxy load balancer.
func NewLoadBalancer(nodes []*BalancerNode) *LoadBalancer {
	return &LoadBalancer{
		nodes: nodes,
	}
}

// SelectNode selects a backend node based on Weighted Round Robin.
func (lb *LoadBalancer) SelectNode() (*BalancerNode, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	var activeNodes []*BalancerNode
	for _, n := range lb.nodes {
		if n.Active {
			activeNodes = append(activeNodes, n)
		}
	}

	if len(activeNodes) == 0 {
		return nil, errors.New("load_balancer: no active nodes available")
	}

	// Calculate total weight
	var totalWeight int32
	for _, n := range activeNodes {
		w := atomic.LoadInt32(&n.Weight)
		if w <= 0 {
			w = 1
		}
		totalWeight += w
	}

	curr := atomic.AddUint64(&lb.counter, 1)
	modVal := int32(curr % uint64(totalWeight))

	var cumulativeWeight int32
	for _, n := range activeNodes {
		w := atomic.LoadInt32(&n.Weight)
		if w <= 0 {
			w = 1
		}
		cumulativeWeight += w
		if modVal < cumulativeWeight {
			return n, nil
		}
	}

	return activeNodes[0], nil
}

// SelectByLatency returns the active node with the lowest latency.
func (lb *LoadBalancer) SelectByLatency() (*BalancerNode, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	var bestNode *BalancerNode
	var bestLatency int64 = mathMaxInt64

	for _, n := range lb.nodes {
		if n.Active {
			lat := atomic.LoadInt64(&n.Latency)
			if lat < bestLatency {
				bestLatency = lat
				bestNode = n
			}
		}
	}

	if bestNode == nil {
		return nil, errors.New("load_balancer: no active nodes available")
	}

	return bestNode, nil
}

const mathMaxInt64 = int64(^uint64(0) >> 1)

// Dial wraps connection establishment to route traffic to the selected node.
func (lb *LoadBalancer) Dial(ctx context.Context, network string) (net.Conn, error) {
	node, err := lb.SelectNode()
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, network, node.Address)
}
