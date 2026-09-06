package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestGenerateState(t *testing.T) {
	s1 := GenerateState()
	s2 := GenerateState()

	if len(s1) != 32 {
		t.Errorf("expected 32 character hex string, got len %d", len(s1))
	}
	if s1 == s2 {
		t.Error("expected randomly generated states to differ")
	}
}

func TestExchangeAndFetchUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id": "12345", "email": "test@luminet.io", "name": "LumiNet Tester"}`))
	}))
	defer server.Close()

	cfg := &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://provider.com/auth",
			TokenURL: server.URL + "/token",
		},
		RedirectURL: "https://localhost/callback",
		Scopes:      []string{"profile", "email"},
	}

	p := NewOAuthProvider(cfg, server.URL)

	if p.Config.ClientID != "client-id" {
		t.Errorf("expected ClientID client-id, got %s", p.Config.ClientID)
	}

	if p.UserInfoURL != server.URL {
		t.Errorf("expected UserInfoURL %s, got %s", server.URL, p.UserInfoURL)
	}

	redirectURL := p.AuthRedirectURL("state-123")
	if redirectURL != "https://provider.com/auth?access_type=offline&client_id=client-id&redirect_uri=https%3A%2F%2Flocalhost%2Fcallback&response_type=code&scope=profile+email&state=state-123" {
		t.Errorf("unexpected redirect URL generated: %s", redirectURL)
	}
}
