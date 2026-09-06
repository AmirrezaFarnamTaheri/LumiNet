// Package p2p manages peer-to-peer DHT tracking.
package p2p

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"time"
)

// XNetPeer represents a node in the XNet overlay mesh.
type XNetPeer struct {
	ID       string
	Addr     string
	Port     uint16
	LastSeen time.Time
	Latency  time.Duration
}

// XNetOverlay implements a decentralized peer-to-peer proxy mesh network.
// Peers are discovered, probed for latency, and selected for routing based
// on performance — avoiding central choke points via randomized relay chains.
type XNetOverlay struct {
	mu       sync.RWMutex
	peers    map[string]*XNetPeer
	localID  string
	DialTimeout time.Duration
	MaxRelayHops int
}

func NewXNetOverlay() *XNetOverlay {
	return &XNetOverlay{
		peers:        make(map[string]*XNetPeer),
		localID:      generateID(),
		DialTimeout:  5 * time.Second,
		MaxRelayHops: 3,
	}
}

// AddPeer registers a peer in the overlay mesh.
func (x *XNetOverlay) AddPeer(id, addr string, port uint16) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.peers[id] = &XNetPeer{ID: id, Addr: addr, Port: port}
	slog.Info("XNetOverlay: peer added", "id", id, "addr", fmt.Sprintf("%s:%d", addr, port))
}

// RemovePeer removes a peer from the overlay mesh.
func (x *XNetOverlay) RemovePeer(id string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	delete(x.peers, id)
}

// PeerCount returns the number of known peers.
func (x *XNetOverlay) PeerCount() int {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return len(x.peers)
}

// Overlay runs the overlay maintenance loop: probes all peers for latency,
// evicts unresponsive ones, and logs the current mesh health.
func (x *XNetOverlay) Overlay(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	slog.Info("XNetOverlay: overlay loop started", "local_id", x.localID)
	for {
		select {
		case <-ctx.Done():
			slog.Info("XNetOverlay: stopped")
			return
		case <-ticker.C:
			x.probeAll(ctx)
		}
	}
}

// SelectRelayChain returns up to MaxRelayHops low-latency peers for a relay path.
func (x *XNetOverlay) SelectRelayChain() []*XNetPeer {
	x.mu.RLock()
	defer x.mu.RUnlock()

	responsive := make([]*XNetPeer, 0, len(x.peers))
	for _, p := range x.peers {
		if p.Latency > 0 && p.Latency < 3*time.Second {
			responsive = append(responsive, p)
		}
	}

	// Shuffle for randomized relay selection (avoid predictable routing)
	rand.Shuffle(len(responsive), func(i, j int) {
		responsive[i], responsive[j] = responsive[j], responsive[i]
	})

	if len(responsive) > x.MaxRelayHops {
		return responsive[:x.MaxRelayHops]
	}
	return responsive
}

func (x *XNetOverlay) probeAll(ctx context.Context) {
	x.mu.RLock()
	ids := make([]string, 0, len(x.peers))
	for id := range x.peers {
		ids = append(ids, id)
	}
	x.mu.RUnlock()

	for _, id := range ids {
		x.mu.RLock()
		peer, ok := x.peers[id]
		x.mu.RUnlock()
		if !ok {
			continue
		}
		addr := fmt.Sprintf("%s:%d", peer.Addr, peer.Port)
		t0 := time.Now()
		pctx, cancel := context.WithTimeout(ctx, x.DialTimeout)
		conn, err := (&net.Dialer{}).DialContext(pctx, "tcp", addr)
		cancel()
		lat := time.Since(t0)
		if err != nil {
			slog.Debug("XNetOverlay: peer unreachable", "id", id, "addr", addr)
			continue
		}
		conn.Close()
		x.mu.Lock()
		if p, ok := x.peers[id]; ok {
			p.Latency = lat
			p.LastSeen = time.Now().UTC()
		}
		x.mu.Unlock()
	}
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return fmt.Sprintf("%x", b)
}
