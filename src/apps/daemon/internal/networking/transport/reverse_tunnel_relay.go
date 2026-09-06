package transport

import (
	"errors"
	"sync"
	"time"
)

// ReverseRelaySession represents an active reverse-tunneled stream connection
type ReverseRelaySession struct {
	SessionID   uint64
	RemoteAddr  string
	TargetAddr  string
	BytesIn     uint64
	BytesOut    uint64
	LastActive  time.Time
	IsConnected bool
}

// ReverseTunnelRelay routes incoming client connections through an established reverse control link
type ReverseTunnelRelay struct {
	sessions    map[uint64]*ReverseRelaySession
	nextID      uint64
	maxSessions int
	mu          sync.RWMutex
}

// NewReverseTunnelRelay creates a new reverse tunnel relay coordinator
func NewReverseTunnelRelay(maxSessions int) *ReverseTunnelRelay {
	if maxSessions <= 0 {
		maxSessions = 1000
	}
	return &ReverseTunnelRelay{
		sessions:    make(map[uint64]*ReverseRelaySession),
		nextID:      1,
		maxSessions: maxSessions,
	}
}

// OpenSession establishes a new reverse tunnel multiplexed session
func (r *ReverseTunnelRelay) OpenSession(remoteAddr, targetAddr string) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.sessions) >= r.maxSessions {
		return 0, errors.New("max reverse tunnel sessions reached")
	}

	id := r.nextID
	r.nextID++

	r.sessions[id] = &ReverseRelaySession{
		SessionID:   id,
		RemoteAddr:  remoteAddr,
		TargetAddr:  targetAddr,
		LastActive:  time.Now(),
		IsConnected: true,
	}
	return id, nil
}

// ForwardData updates traffic byte counters for a session
func (r *ReverseTunnelRelay) ForwardData(sessionID uint64, bytesIn, bytesOut uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, exists := r.sessions[sessionID]
	if !exists || !session.IsConnected {
		return errors.New("session closed or not found")
	}

	session.BytesIn += bytesIn
	session.BytesOut += bytesOut
	session.LastActive = time.Now()
	return nil
}

// CloseSession terminates a reverse session
func (r *ReverseTunnelRelay) CloseSession(sessionID uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	session, exists := r.sessions[sessionID]
	if !exists {
		return false
	}
	session.IsConnected = false
	delete(r.sessions, sessionID)
	return true
}

// ActiveSessionsCount returns currently connected reverse sessions
func (r *ReverseTunnelRelay) ActiveSessionsCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}
