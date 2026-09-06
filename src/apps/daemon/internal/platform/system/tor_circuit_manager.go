// Package system provides platform and system orchestration routines for LumiNet.
//
// Tracks live Tor circuits by random 32-bit ID. Caps concurrency to bound
// memory and to keep the directory authority's rate of NEWCIRCUIT requests
// within the recommended client ceiling (control-spec §4.1.1).

package system

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"
)

// CircuitID is a 32-bit random circuit identifier as exposed on the
// control port via CIRCUIT events. uint32 matches the unsigned STATUS/
// CIRCUIT reply field width.
type CircuitID uint32

// Circuit is the manager-side view of a Tor circuit: the path of relay
// fingerprints, creation timestamp, and liveness flag.
type Circuit struct {
	ID        CircuitID
	Path      []string
	CreatedAt time.Time
	Closed    bool
}

// CircuitManager owns a bounded map of live circuits.
//
// ponytail: map+CircuitID is a flat index. When circuit counts grow past
// tens of thousands per process, move to a sharded map (per-CPU lock)
// to keep lock contention off the hot stream-attach path.
type CircuitManager struct {
	mu          sync.RWMutex
	circuits    map[CircuitID]*Circuit
	maxCircuits int
}

// NewCircuitManager builds a manager capped at `maxCircuits`. A value <= 0
// falls back to 100, the recommended client-side ceiling for non-bulk
// use (tor-spec, §5 BUILDING CIRCUITS).
func NewCircuitManager(maxCircuits int) *CircuitManager {
	if maxCircuits <= 0 {
		maxCircuits = 100
	}
	return &CircuitManager{
		circuits:    make(map[CircuitID]*Circuit),
		maxCircuits: maxCircuits,
	}
}

// Create allocates a new circuit over `path` (an ordered list of relay
// fingerprints). Returns an error if the manager is at capacity. CircuitID
// is drawn from crypto/rand with up to 8 retries on collision.
func (m *CircuitManager) Create(path []string) (*Circuit, error) {
	id, err := m.allocID()
	if err != nil {
		return nil, err
	}
	c := &Circuit{
		ID:        id,
		Path:      append([]string(nil), path...),
		CreatedAt: time.Now(),
	}
	m.mu.Lock()
	if len(m.circuits) >= m.maxCircuits {
		m.mu.Unlock()
		return nil, fmt.Errorf("circuit_manager: at capacity %d", m.maxCircuits)
	}
	m.circuits[id] = c
	m.mu.Unlock()
	return c, nil
}

// Get fetches a circuit by ID. Returns nil, false when absent or closed.
func (m *CircuitManager) Get(id CircuitID) (*Circuit, bool) {
	m.mu.RLock()
	c, ok := m.circuits[id]
	m.mu.RUnlock()
	if !ok || c.Closed {
		return nil, false
	}
	return c, true
}

// Close marks a circuit closed and removes it from the map. Returns an
// error when the circuit was never known.
func (m *CircuitManager) Close(id CircuitID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.circuits[id]
	if !ok {
		return fmt.Errorf("circuit_manager: id %d not found", id)
	}
	c.Closed = true
	delete(m.circuits, id)
	return nil
}

// CloseAll marks every tracked circuit closed and drops the map state.
func (m *CircuitManager) CloseAll() {
	m.mu.Lock()
	for _, c := range m.circuits {
		c.Closed = true
	}
	m.circuits = make(map[CircuitID]*Circuit)
	m.mu.Unlock()
}

// Count returns the current number of live (non-closed) circuits.
func (m *CircuitManager) Count() int {
	m.mu.RLock()
	n := len(m.circuits)
	m.mu.RUnlock()
	return n
}

// Active returns a snapshot slice of all non-closed circuits.
func (m *CircuitManager) Active() []*Circuit {
	m.mu.RLock()
	out := make([]*Circuit, 0, len(m.circuits))
	for _, c := range m.circuits {
		if !c.Closed {
			out = append(out, c)
		}
	}
	m.mu.RUnlock()
	return out
}

// allocID draws a 32-bit random CircuitID, retrying up to 8 times if the
// ID collides with a live circuit. Returns an error only if all 8 draws
// collide (cryptographically improbable).
func (m *CircuitManager) allocID() (CircuitID, error) {
	var buf [4]byte
	for i := 0; i < 8; i++ {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("circuit_manager: rand: %w", err)
		}
		id := CircuitID(uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3]))
		if id == 0 {
			continue // 0 is Tor's "uninitialized" sentinel.
		}
		m.mu.RLock()
		_, exists := m.circuits[id]
		m.mu.RUnlock()
		if !exists {
			return id, nil
		}
	}
	return 0, errors.New("circuit_manager: could not allocate unique id after 8 tries")
}
