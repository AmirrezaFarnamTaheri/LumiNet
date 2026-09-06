// Ported from: metapi-main
// Target path: server/internal/proxy/conductor.go

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// ConductorOutbound represents an outbound proxy interface that can dial connections.
type ConductorOutbound interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Name() string
}

// Conductor manages outbounds, retries, and latency-based failovers.
type Conductor struct {
	mu         sync.RWMutex
	outbounds  []ConductorOutbound
	failures   map[string]int
	maxRetries int
	timeout    time.Duration
}

// NewConductor creates a new proxy conductor.
func NewConductor(outbounds []ConductorOutbound, maxRetries int, timeout time.Duration) *Conductor {
	if maxRetries <= 0 {
		maxRetries = 3
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Conductor{
		outbounds:  outbounds,
		failures:   make(map[string]int),
		maxRetries: maxRetries,
		timeout:    timeout,
	}
}

// Dial dials the target address by selecting outbounds in order.
// If one fails, it retries with the next available outbound.
func (c *Conductor) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.RLock()
	nodes := make([]ConductorOutbound, len(c.outbounds))
	copy(nodes, c.outbounds)
	c.mu.RUnlock()

	if len(nodes) == 0 {
		return nil, errors.New("conductor: no outbounds configured")
	}

	var lastErr error
	for _, node := range nodes {
		// Skip nodes that have failed too many times
		c.mu.RLock()
		fails := c.failures[node.Name()]
		c.mu.RUnlock()
		if fails >= c.maxRetries {
			continue
		}

		dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
		conn, err := node.DialContext(dialCtx, network, address)
		cancel()

		if err == nil {
			// Success, reset failure count
			c.mu.Lock()
			c.failures[node.Name()] = 0
			c.mu.Unlock()
			return conn, nil
		}

		lastErr = err
		// Record failure
		c.mu.Lock()
		c.failures[node.Name()]++
		c.mu.Unlock()
	}

	return nil, fmt.Errorf("conductor: all outbounds failed, last error: %w", lastErr)
}

// ResetFailures clears failure counts for all nodes.
func (c *Conductor) ResetFailures() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = make(map[string]int)
}

// SetOutbounds updates the list of active outbounds.
func (c *Conductor) SetOutbounds(outbounds []ConductorOutbound) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outbounds = outbounds
}
