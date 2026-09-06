package backhaul

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// BackhaulMux manages connection load-balancing across active egress sessions.
type BackhaulMux struct {
	mu      sync.RWMutex
	conns   []net.Conn
	counter uint64
}

// NewBackhaulMux creates an empty BackhaulMux.
func NewBackhaulMux() *BackhaulMux {
	return &BackhaulMux{conns: make([]net.Conn, 0)}
}

// AddConn registers an active transport connection to the multiplexer pool.
func (m *BackhaulMux) AddConn(conn net.Conn) {
	if conn == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conns = append(m.conns, conn)
}

// RemoveConn unregisters a connection from the pool.
func (m *BackhaulMux) RemoveConn(conn net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, c := range m.conns {
		if c == conn {
			m.conns = append(m.conns[:i], m.conns[i+1:]...)
			return
		}
	}
}

// NextConn returns the next connection in round-robin sequence.
func (m *BackhaulMux) NextConn() (net.Conn, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.conns) == 0 {
		return nil, errors.New("no active backhaul connections available")
	}

	idx := atomic.AddUint64(&m.counter, 1) % uint64(len(m.conns))
	return m.conns[idx], nil
}

// ActiveCount returns the total number of registered connections.
func (m *BackhaulMux) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.conns)
}
