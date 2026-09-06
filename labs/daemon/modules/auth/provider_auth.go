package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// OAuthProvider configures the handlers for external providers (Google, GitHub, etc.).
type OAuthProvider struct {
	Config      *oauth2.Config
	UserInfoURL string
}

// UserInfo represents basic OAuth user profile info returned by providers.
type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// NewOAuthProvider creates a provider instance.
func NewOAuthProvider(config *oauth2.Config, userInfoURL string) *OAuthProvider {
	return &OAuthProvider{
		Config:      config,
		UserInfoURL: userInfoURL,
	}
}

// GenerateState generates a random state string for CSRF protection.
func GenerateState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// AuthRedirectURL returns the URL to redirect the user to for authentication.
func (p *OAuthProvider) AuthRedirectURL(state string) string {
	return p.Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeAndFetchUser exchanges the auth code for a token and fetches user info.
func (p *OAuthProvider) ExchangeAndFetchUser(ctx context.Context, code string) (*UserInfo, error) {
	token, err := p.Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oauth: token exchange failed: %w", err)
	}

	client := p.Config.Client(ctx, token)
	resp, err := client.Get(p.UserInfoURL)
	if err != nil {
		return nil, fmt.Errorf("oauth: failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth: non-ok status fetching user info: %s", resp.Status)
	}

	var info UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("oauth: failed to decode user info: %w", err)
	}

	if info.ID == "" {
		return nil, errors.New("oauth: empty user ID returned by provider")
	}

	return &info, nil
}
