package transport

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// RendezvousSession represents a paired connection state.
type RendezvousSession struct {
	SessionToken string    `json:"session_token"`
	Initiator    string    `json:"initiator"`
	Responder    string    `json:"responder"`
	CreatedAt    time.Time `json:"created_at"`
	IsConnected  bool      `json:"is_connected"`
}

// RendezvousBridge manages rendezvous tokens and peer bridging.
type RendezvousBridge struct {
	mu       sync.Mutex
	sessions map[string]*RendezvousSession
	ttl      time.Duration
}

// NewRendezvousBridge constructs an active bridge manager.
func NewRendezvousBridge(ttl time.Duration) *RendezvousBridge {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &RendezvousBridge{
		sessions: make(map[string]*RendezvousSession),
		ttl:      ttl,
	}
}

// RegisterPeer registers an initiator and returns a 16-byte hex token.
func (b *RendezvousBridge) RegisterPeer(peerAddr string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(bytes)

	b.sessions[token] = &RendezvousSession{
		SessionToken: token,
		Initiator:    peerAddr,
		CreatedAt:    time.Now(),
		IsConnected:  false,
	}
	return token, nil
}

// ConnectPeer completes the pairing with the responder peer.
func (b *RendezvousBridge) ConnectPeer(token, responderAddr string) (*RendezvousSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	sess, exists := b.sessions[token]
	if !exists {
		return nil, fmt.Errorf("session token not found or expired")
	}

	if time.Since(sess.CreatedAt) > b.ttl {
		delete(b.sessions, token)
		return nil, fmt.Errorf("session token expired")
	}

	if sess.IsConnected {
		return nil, fmt.Errorf("session already paired")
	}

	sess.Responder = responderAddr
	sess.IsConnected = true
	return sess, nil
}

// GetSession retrieves current session status.
func (b *RendezvousBridge) GetSession(token string) (*RendezvousSession, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	sess, exists := b.sessions[token]
	return sess, exists
}
