// Package proxy implements the in-flight deduplication manager ported from MasterDnsVPN-main.
// Source: internal/inflight/manager.go
// Target: server/internal/proxy/masterdnsvpn_inflight.go

package proxy

import (
	"sync"
	"time"
)

// DNSVPNInflightEntry holds the state for a single in-flight VPN request.
// Source: inflight/manager.go Entry[T]
type DNSVPNInflightEntry struct {
	createdAt time.Time
	ready     chan struct{}
	value     []byte
	hasValue  bool
}

func (e *DNSVPNInflightEntry) GetCreatedAt() time.Time { return e.createdAt }
func (e *DNSVPNInflightEntry) GetHasValue() bool       { return e.hasValue }
func (e *DNSVPNInflightEntry) GetValue() []byte        { return e.value }

// DNSVPNInflightManager deduplicates concurrent VPN DNS lookups for the same key.
// Source: inflight/manager.go Manager[T]
type DNSVPNInflightManager struct {
	timeout       time.Duration
	cleanupWindow time.Duration
	nextCleanupAt time.Time
	mu            sync.Mutex
	items         map[string]*DNSVPNInflightEntry
}

// NewDNSVPNInflightManager creates a new in-flight request deduplicator.
// Source: inflight/manager.go New[T]
func NewDNSVPNInflightManager(timeout, fallback time.Duration) *DNSVPNInflightManager {
	if timeout <= 0 {
		timeout = fallback
	}
	cleanupWindow := timeout / 4
	if cleanupWindow < time.Second {
		cleanupWindow = time.Second
	}
	return &DNSVPNInflightManager{
		timeout:       timeout,
		cleanupWindow: cleanupWindow,
		items:         make(map[string]*DNSVPNInflightEntry),
	}
}

// Acquire either returns an existing entry (leader=false) or creates a new one (leader=true).
// Source: inflight/manager.go Manager[T].Acquire
func (m *DNSVPNInflightManager) Acquire(key string, now time.Time) (*DNSVPNInflightEntry, bool) {
	if m == nil || key == "" {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.nextCleanupAt.IsZero() || !now.Before(m.nextCleanupAt) {
		for existingKey, entry := range m.items {
			if entry == nil || now.Sub(entry.createdAt) >= m.timeout {
				delete(m.items, existingKey)
			}
		}
		m.nextCleanupAt = now.Add(m.cleanupWindow)
	}

	if entry, ok := m.items[key]; ok && entry != nil && now.Sub(entry.createdAt) < m.timeout {
		return entry, false
	}

	entry := &DNSVPNInflightEntry{
		createdAt: now,
		ready:     make(chan struct{}),
	}
	m.items[key] = entry
	return entry, true
}

// Begin returns true if this caller is the leader for the given key.
// Source: inflight/manager.go Manager[T].Begin
func (m *DNSVPNInflightManager) Begin(key string, now time.Time) bool {
	_, leader := m.Acquire(key, now)
	return leader
}

// Resolve sets the value for a key and unblocks all waiters.
// Source: inflight/manager.go Manager[T].Resolve
func (m *DNSVPNInflightManager) Resolve(key string, value []byte, hasValue bool) {
	if m == nil || key == "" {
		return
	}
	m.mu.Lock()
	entry := m.items[key]
	delete(m.items, key)
	if entry != nil && hasValue {
		cp := make([]byte, len(value))
		copy(cp, value)
		entry.value = cp
		entry.hasValue = true
	}
	m.mu.Unlock()
	if entry != nil {
		close(entry.ready)
	}
}

// Wait blocks until the entry is resolved or the timeout expires.
// Source: inflight/manager.go Manager[T].Wait
func (m *DNSVPNInflightManager) Wait(entry *DNSVPNInflightEntry, timeout time.Duration) ([]byte, bool) {
	if entry == nil {
		return nil, false
	}
	if timeout <= 0 {
		timeout = m.timeout
	}
	if timeout <= 0 {
		return nil, false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-entry.ready:
		if !entry.hasValue {
			return nil, true
		}
		cp := make([]byte, len(entry.value))
		copy(cp, entry.value)
		return cp, true
	case <-timer.C:
		return nil, false
	}
}

// GetTimeout returns the configured deduplication timeout.
func (m *DNSVPNInflightManager) GetTimeout() time.Duration { return m.timeout }

// GetCleanupWindow returns the internal cleanup window duration.
func (m *DNSVPNInflightManager) GetCleanupWindow() time.Duration { return m.cleanupWindow }
