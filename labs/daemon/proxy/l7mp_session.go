// Package proxy implements multi-protocol proxy servers and clients.
// Ported from: l7mp-master (session.js, stream-counter.js)
// Target path: server/internal/proxy/l7mp_session.go

package proxy

import (
	"sync"
	"time"
)

// L7MPSession represents a proxy connection session.
// Maps to Node.js Session in session.js.
type L7MPSession struct {
	SessionID string    `json:"session_id"`
	Protocol  string    `json:"protocol"` // VLESS, Shadowsocks, HTTP, etc.
	SrcAddr   string    `json:"src_addr"`
	DstAddr   string    `json:"dst_addr"`
	RxBytes   int64     `json:"rx_bytes"`
	TxBytes   int64     `json:"tx_bytes"`
	State     string    `json:"state"` // active, closed, idle
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Getters & Setters for L7MPSession
func (s *L7MPSession) GetSessionID() string  { return s.SessionID }
func (s *L7MPSession) SetSessionID(v string) { s.SessionID = v }
func (s *L7MPSession) GetRxBytes() int64     { return s.RxBytes }
func (s *L7MPSession) SetRxBytes(v int64)    { s.RxBytes = v }

// L7MPSessionRegistry manages active layer-7 proxy sessions.
type L7MPSessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]*L7MPSession
}

// NewL7MPSessionRegistry creates a session registry.
func NewL7MPSessionRegistry() *L7MPSessionRegistry {
	return &L7MPSessionRegistry{
		sessions: make(map[string]*L7MPSession),
	}
}

// AddSession registers a new session.
func (r *L7MPSessionRegistry) AddSession(sess *L7MPSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now()
	}
	sess.UpdatedAt = time.Now()
	r.sessions[sess.SessionID] = sess
}

// UpdateTraffic updates session bytes.
func (r *L7MPSessionRegistry) UpdateTraffic(sessionID string, rx, tx int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sess, ok := r.sessions[sessionID]; ok {
		sess.RxBytes += rx
		sess.TxBytes += tx
		sess.UpdatedAt = time.Now()
	}
}

// CloseSession marks session closed.
func (r *L7MPSessionRegistry) CloseSession(sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sess, ok := r.sessions[sessionID]; ok {
		sess.State = "closed"
		sess.UpdatedAt = time.Now()
	}
}

// GetActiveSessions returns list of non-closed sessions.
func (r *L7MPSessionRegistry) GetActiveSessions() []L7MPSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var active []L7MPSession
	for _, sess := range r.sessions {
		if sess.State != "closed" {
			active = append(active, *sess)
		}
	}
	return active
}
