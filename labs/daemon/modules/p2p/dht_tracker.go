// Package p2p manages peer-to-peer DHT tracking.
package p2p

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// DHTNode represents a peer in the distributed proxy swarm.
type DHTNode struct {
	ID        string
	Addr      string
	LastSeen  time.Time
	ProxyPort uint16
}

// DHTTracker maintains a DHT-style node table mapping active proxy instances
// into a decentralized swarm topology. Nodes are pinged periodically and
// evicted when they go silent beyond the stale threshold.
type DHTTracker struct {
	mu             sync.RWMutex
	nodes          map[string]*DHTNode // id -> node
	StaleThreshold time.Duration
	PingInterval   time.Duration
}

func NewDHTTracker() *DHTTracker {
	return &DHTTracker{
		nodes:          make(map[string]*DHTNode),
		StaleThreshold: 5 * time.Minute,
		PingInterval:   30 * time.Second,
	}
}

// Register adds or updates a node in the tracker table.
func (d *DHTTracker) Register(id, addr string, proxyPort uint16) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nodes[id] = &DHTNode{
		ID:        id,
		Addr:      addr,
		LastSeen:  time.Now().UTC(),
		ProxyPort: proxyPort,
	}
	slog.Info("DHTTracker: node registered", "id", id, "addr", addr)
}

// Seen refreshes the last-seen timestamp for an existing node.
func (d *DHTTracker) Seen(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n, ok := d.nodes[id]; ok {
		n.LastSeen = time.Now().UTC()
		return true
	}
	return false
}

// ActiveNodes returns all nodes seen within the stale threshold.
func (d *DHTTracker) ActiveNodes() []*DHTNode {
	d.mu.RLock()
	defer d.mu.RUnlock()
	cutoff := time.Now().UTC().Add(-d.StaleThreshold)
	var out []*DHTNode
	for _, n := range d.nodes {
		if n.LastSeen.After(cutoff) {
			out = append(out, n)
		}
	}
	return out
}

// Evict removes nodes that haven't been seen within the stale threshold.
func (d *DHTTracker) Evict() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().UTC().Add(-d.StaleThreshold)
	evicted := 0
	for id, n := range d.nodes {
		if n.LastSeen.Before(cutoff) {
			delete(d.nodes, id)
			evicted++
			slog.Info("DHTTracker: evicted stale node", "id", id)
		}
	}
	return evicted
}

// Track runs a background maintenance loop that pings all known nodes and evicts stale ones.
// It uses TCP dial as a liveness check against each node's proxy port.
func (d *DHTTracker) Track(ctx context.Context) {
	ticker := time.NewTicker(d.PingInterval)
	defer ticker.Stop()
	slog.Info("DHTTracker: maintenance loop started", "interval", d.PingInterval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("DHTTracker: stopped")
			return
		case <-ticker.C:
			d.pingAll(ctx)
			evicted := d.Evict()
			if evicted > 0 {
				slog.Info("DHTTracker: eviction run", "evicted", evicted, "active", len(d.ActiveNodes()))
			}
		}
	}
}

func (d *DHTTracker) pingAll(ctx context.Context) {
	nodes := d.ActiveNodes()
	for _, n := range nodes {
		addr := fmt.Sprintf("%s:%d", n.Addr, n.ProxyPort)
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err := (&net.Dialer{}).DialContext(pctx, "tcp", addr)
		cancel()
		if err != nil {
			slog.Debug("DHTTracker: node unreachable", "id", n.ID, "addr", addr)
			continue
		}
		conn.Close()
		d.Seen(n.ID)
	}
}
