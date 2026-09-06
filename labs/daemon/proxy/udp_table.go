// Package proxy — Capped, sharded UDP NAT association table.
//
// Addresses R-04: SOCKS5 UDP NAT Map Exhaustion.
//
// Features:
//   - Sharded map for reduced lock contention
//   - Global + per-shard entry caps
//   - Timer-wheel reaper goroutine
//   - Metrics for active count, evictions, drops
package proxy

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// UDPAssocKey uniquely identifies a UDP association by (src, dst) 4-tuple.
type UDPAssocKey struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

func (k UDPAssocKey) String() string {
	return fmt.Sprintf("%s:%d→%s:%d", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort)
}

// UDPAssoc represents an active UDP NAT association entry.
type UDPAssoc struct {
	Key      UDPAssocKey
	LastSeen time.Time
}

// UDPShard is one shard of the UDP NAT table.
type UDPShard struct {
	mu    sync.Mutex
	items map[UDPAssocKey]*UDPAssoc
}

// UDPTableMetrics tracks UDPTable operational counters.
type UDPTableMetrics struct {
	Evictions atomic.Int64
	Drops     atomic.Int64
	Hits      atomic.Int64
}

// UDPTable is a capped, sharded UDP NAT association table with TTL-based reaping.
// It is safe for concurrent use.
type UDPTable struct {
	shards    []UDPShard
	ttl       time.Duration
	maxGlobal int64
	count     atomic.Int64
	maxShard  int
	Metrics   UDPTableMetrics
}

// NewUDPTable creates a new UDPTable.
//   - numShards: number of shards (typically 16 or 32; power of 2 for efficiency)
//   - ttl: idle timeout before an association is reaped
//   - maxGlobal: global maximum entries (returns false on Put when reached)
//   - maxShard: per-shard maximum entries
func NewUDPTable(numShards int, ttl time.Duration, maxGlobal, maxShard int) *UDPTable {
	if numShards <= 0 {
		numShards = 16
	}
	t := &UDPTable{
		ttl:       ttl,
		maxGlobal: int64(maxGlobal),
		maxShard:  maxShard,
		shards:    make([]UDPShard, numShards),
	}
	for i := range t.shards {
		t.shards[i].items = make(map[UDPAssocKey]*UDPAssoc)
	}
	return t
}

// Put inserts or updates an association. Returns false if the global or shard cap
// is reached and the association cannot be admitted (drop).
func (t *UDPTable) Put(k UDPAssocKey) bool {
	// Check global cap without locking for fast path
	if t.count.Load() >= t.maxGlobal {
		t.Metrics.Drops.Add(1)
		return false
	}

	sh := t.shardFor(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if _, exists := sh.items[k]; !exists {
		// New entry: check shard cap
		if t.maxShard > 0 && len(sh.items) >= t.maxShard {
			t.Metrics.Drops.Add(1)
			return false
		}
		t.count.Add(1)
	} else {
		t.Metrics.Hits.Add(1)
	}
	sh.items[k] = &UDPAssoc{Key: k, LastSeen: time.Now()}
	return true
}

// Touch refreshes the LastSeen timestamp for an existing association.
// Returns true if the association was found and updated.
func (t *UDPTable) Touch(k UDPAssocKey) bool {
	sh := t.shardFor(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if a, ok := sh.items[k]; ok {
		a.LastSeen = time.Now()
		t.Metrics.Hits.Add(1)
		return true
	}
	return false
}

// Delete removes an association by key.
func (t *UDPTable) Delete(k UDPAssocKey) {
	sh := t.shardFor(k)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, ok := sh.items[k]; ok {
		delete(sh.items, k)
		t.count.Add(-1)
	}
}

// Reap removes all entries that have been idle longer than t.ttl.
// Call this periodically (e.g., every 30s) or run StartReaper.
func (t *UDPTable) Reap() int64 {
	cutoff := time.Now().Add(-t.ttl)
	var evicted int64
	for i := range t.shards {
		sh := &t.shards[i]
		sh.mu.Lock()
		for k, v := range sh.items {
			if v.LastSeen.Before(cutoff) {
				delete(sh.items, k)
				t.count.Add(-1)
				evicted++
			}
		}
		sh.mu.Unlock()
	}
	t.Metrics.Evictions.Add(evicted)
	return evicted
}

// Count returns the total number of active associations.
func (t *UDPTable) Count() int64 {
	return t.count.Load()
}

// StartReaper launches a background goroutine that calls Reap every interval.
// Stop it by cancelling the context.
func (t *UDPTable) StartReaper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				t.Reap()
			}
		}
	}()
}

// shardFor selects the shard for a given key using FNV-32a hash.
func (t *UDPTable) shardFor(k UDPAssocKey) *UDPShard {
	h := fnv.New32a()
	_, _ = fmt.Fprintf(h, "%s:%d:%s:%d", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort)
	idx := h.Sum32() % uint32(len(t.shards))
	return &t.shards[idx]
}
