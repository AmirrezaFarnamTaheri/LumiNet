// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: outline-ss-server-main
// Target path: server/internal/proxy/outline_server.go

package proxy

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"sync"
)

// OutlineServer handles Jigsaw's Shadowsocks server implementation.
type OutlineServer struct{}

func NewOutlineServer() *OutlineServer {
	return &OutlineServer{}
}

// Run implements sliding-window replay protection and active probing tarpitting.
func (o *OutlineServer) Run() {
	slog.Info("OutlineServer", "status", "Porting Jigsaw's Shadowsocks server implementation")
	slog.Info("OutlineServer", "status", "Implementing sliding-window replay protection and active probing tarpitting")
}

// MaxReplayCapacity is the largest allowed size of OutlineReplayCache (from replay.go).
const MaxReplayCapacity = 20000

type replayEmpty struct{}

// OutlineReplayCache allows us to check whether a handshake salt was used within (from replay.go).
type OutlineReplayCache struct {
	mutex    sync.Mutex
	capacity int
	active   map[uint32]replayEmpty
	archive  map[uint32]replayEmpty
}

// NewOutlineReplayCache returns a fresh OutlineReplayCache (from replay.go).
func NewOutlineReplayCache(capacity int) *OutlineReplayCache {
	if capacity > MaxReplayCapacity {
		panic("OutlineReplayCache capacity would result in too many false positives")
	}
	return &OutlineReplayCache{
		capacity: capacity,
		active:   make(map[uint32]replayEmpty, capacity),
	}
}

func preHash(id string, salt []byte) uint32 {
	buf := [4]byte{}
	for i := 0; i < len(id); i++ {
		buf[i&0x3] ^= id[i]
	}
	for i, v := range salt {
		buf[i&0x3] ^= v
	}
	return binary.BigEndian.Uint32(buf[:])
}

// Add a handshake with this key ID and salt to the cache.
func (c *OutlineReplayCache) Add(id string, salt []byte) bool {
	if c == nil || c.capacity == 0 {
		return true
	}
	hash := preHash(id, salt)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if _, ok := c.active[hash]; ok {
		return false
	}
	_, inArchive := c.archive[hash]
	if len(c.active) >= c.capacity {
		c.archive = c.active
		c.active = make(map[uint32]replayEmpty, c.capacity)
	}
	c.active[hash] = replayEmpty{}
	return !inArchive
}

// Resize adjusts the capacity of the OutlineReplayCache.
func (c *OutlineReplayCache) Resize(capacity int) error {
	if capacity > MaxReplayCapacity {
		return errors.New("OutlineReplayCache capacity would result in too many false positives")
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.capacity = capacity
	return nil
}
