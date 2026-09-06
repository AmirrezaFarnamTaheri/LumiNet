package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const websocketSessionTTL = time.Minute

type websocketSessionIssuer struct {
	mu     sync.Mutex
	tokens map[string]time.Time
}

func newWebsocketSessionIssuer() *websocketSessionIssuer {
	return &websocketSessionIssuer{tokens: make(map[string]time.Time)}
}

func (i *websocketSessionIssuer) issue(now time.Time) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expiresAt := now.Add(websocketSessionTTL)
	i.mu.Lock()
	defer i.mu.Unlock()
	for value, expiry := range i.tokens {
		if !expiry.After(now) {
			delete(i.tokens, value)
		}
	}
	i.tokens[token] = expiresAt
	return token, expiresAt, nil
}

func (i *websocketSessionIssuer) consume(token string, now time.Time) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	expiresAt, ok := i.tokens[token]
	if !ok {
		return false
	}
	delete(i.tokens, token)
	return expiresAt.After(now)
}

func (s *Server) issueWebsocketSession(c *gin.Context) {
	token, expiresAt, err := s.wsSessions.issue(time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create websocket session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token, "expires_at": expiresAt.UTC()})
}
