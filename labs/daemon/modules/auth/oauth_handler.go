// Ported from: gologin-main
// Target path: server/internal/auth/oauth_handler.go

package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// OAuthHandler coordinates OAuth2 authentication flows.
type OAuthHandler struct {
	mu           sync.Mutex
	config       *oauth2.Config
	stateTokens  map[string]time.Time
	tokenTimeout time.Duration
}

// NewOAuthHandler creates a new OAuth2 handler.
func NewOAuthHandler(config *oauth2.Config) *OAuthHandler {
	return &OAuthHandler{
		config:       config,
		stateTokens:  make(map[string]time.Time),
		tokenTimeout: 10 * time.Minute,
	}
}

// GenerateState generates a random state token and registers it for validation.
func (h *OAuthHandler) GenerateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth_handler: generate state: %w", err)
	}
	state := base64.URLEncoding.EncodeToString(b)

	h.mu.Lock()
	h.stateTokens[state] = time.Now()
	h.mu.Unlock()

	return state, nil
}

// ValidateState checks if the state token is valid and not expired.
func (h *OAuthHandler) ValidateState(state string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	created, ok := h.stateTokens[state]
	if !ok {
		return false
	}
	delete(h.stateTokens, state) // state token is single-use

	return time.Since(created) <= h.tokenTimeout
}

// GetAuthURL returns the URL to redirect the user to for authentication.
func (h *OAuthHandler) GetAuthURL(state string) string {
	return h.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeToken exchanges an authorization code for an OAuth2 token.
func (h *OAuthHandler) ExchangeToken(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := h.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oauth_handler: exchange token failed: %w", err)
	}
	return token, nil
}

// ServeHTTP handles the incoming callback request from the OAuth2 provider.
func (h *OAuthHandler) HandleCallback(w http.ResponseWriter, r *http.Request, successHandler func(http.ResponseWriter, *http.Request, *oauth2.Token)) {
	state := r.URL.Query().Get("state")
	if !h.ValidateState(state) {
		http.Error(w, "invalid or expired state token", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := h.ExchangeToken(r.Context(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	successHandler(w, r, token)
}
