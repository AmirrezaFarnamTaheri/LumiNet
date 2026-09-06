// Package system handles platform-specific parameters, routing, and cert configurations.

package system

import (
	"strings"
	"sync"
	"time"
)

// NetfoilTrieNode represents a node in the suffix search trie.
type NetfoilTrieNode struct {
	Children map[string]*NetfoilTrieNode
	IsLeaf   bool
	Payload  string
}

// NetfoilTrie manages prefix matching operations.
type NetfoilTrie struct {
	mu   sync.RWMutex
	Root *NetfoilTrieNode
	Size int
}

// NewNetfoilTrie initializes suffix trie.
func NewNetfoilTrie() *NetfoilTrie {
	return &NetfoilTrie{
		Root: &NetfoilTrieNode{
			Children: make(map[string]*NetfoilTrieNode),
		},
	}
}

// Insert adds domain suffixes to trie.
func (t *NetfoilTrie) Insert(domain string, payload string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	parts := strings.Split(domain, ".")
	curr := t.Root
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if _, ok := curr.Children[part]; !ok {
			curr.Children[part] = &NetfoilTrieNode{
				Children: make(map[string]*NetfoilTrieNode),
			}
		}
		curr = curr.Children[part]
	}
	curr.IsLeaf = true
	curr.Payload = payload
	t.Size++
}

// Search checks if suffix matches inside the trie.
func (t *NetfoilTrie) Search(domain string) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	parts := strings.Split(domain, ".")
	curr := t.Root
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if next, ok := curr.Children[part]; ok {
			curr = next
			if curr.IsLeaf {
				return curr.Payload, true
			}
		} else {
			break
		}
	}
	return "", false
}

// NetfoilLRUEntry holds cached data.
type NetfoilLRUEntry struct {
	Key       string
	Value     interface{}
	ExpiresAt time.Time
}

// NetfoilLRUCache enforces storage limits.
type NetfoilLRUCache struct {
	mu       sync.Mutex
	Capacity int
	CacheMap map[string]*NetfoilLRUEntry
}

// NewNetfoilLRUCache creates cache registry.
func NewNetfoilLRUCache(capacity int) *NetfoilLRUCache {
	return &NetfoilLRUCache{
		Capacity: capacity,
		CacheMap: make(map[string]*NetfoilLRUEntry),
	}
}

// Get retrieves cache value.
func (c *NetfoilLRUCache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.CacheMap[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		delete(c.CacheMap, key)
		return nil, false
	}
	return entry.Value, true
}

// Set stores cache values.
func (c *NetfoilLRUCache) Set(key string, value interface{}, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.CacheMap) >= c.Capacity {
		// Evict first found (simple eviction helper)
		for k := range c.CacheMap {
			delete(c.CacheMap, k)
			break
		}
	}
	c.CacheMap[key] = &NetfoilLRUEntry{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().Add(duration),
	}
}

// Additional getters & setters for NetfoilLRUEntry
func (e *NetfoilLRUEntry) GetKey() string           { return e.Key }
func (e *NetfoilLRUEntry) SetKey(v string)          { e.Key = v }
func (e *NetfoilLRUEntry) GetValue() interface{}    { return e.Value }
func (e *NetfoilLRUEntry) SetValue(v interface{})   { e.Value = v }
func (e *NetfoilLRUEntry) GetExpiresAt() time.Time  { return e.ExpiresAt }
func (e *NetfoilLRUEntry) SetExpiresAt(v time.Time) { e.ExpiresAt = v }

// Additional getters & setters for NetfoilLRUCache
func (c *NetfoilLRUCache) GetCapacity() int  { return c.Capacity }
func (c *NetfoilLRUCache) SetCapacity(v int) { c.Capacity = v }
func (c *NetfoilLRUCache) GetSize() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.CacheMap)
}

// Additional getters & setters for NetfoilTrie
func (t *NetfoilTrie) GetSize() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Size
}
func (t *NetfoilTrie) IsEmpty() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Size == 0
}
func (t *NetfoilTrie) GetRoot() *NetfoilTrieNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Root
}
func (t *NetfoilTrie) SetRoot(v *NetfoilTrieNode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Root = v
}

// Getters & Setters for NetfoilTrieNode
func (n *NetfoilTrieNode) GetChildren() map[string]*NetfoilTrieNode  { return n.Children }
func (n *NetfoilTrieNode) SetChildren(v map[string]*NetfoilTrieNode) { n.Children = v }
func (n *NetfoilTrieNode) GetIsLeaf() bool                           { return n.IsLeaf }
func (n *NetfoilTrieNode) SetIsLeaf(v bool)                          { n.IsLeaf = v }
func (n *NetfoilTrieNode) GetPayload() string                        { return n.Payload }
func (n *NetfoilTrieNode) SetPayload(v string)                       { n.Payload = v }
