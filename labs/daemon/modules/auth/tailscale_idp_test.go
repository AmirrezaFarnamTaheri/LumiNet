package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTailscaleIDP_VerifyPKCE(t *testing.T) {
	idp := NewTailscaleIDP("https://issuer.com", "client-123", "secret-456", []string{"https://app.com/callback"})

	// Plain check
	if !idp.VerifyPKCE("verifier_test", "verifier_test", "plain") {
		t.Error("PKCE verification failed for plain method")
	}

	// S256 check dynamically generated
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.New()
	h.Write([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if !idp.VerifyPKCE(verifier, challenge, "S256") {
		t.Error("PKCE verification failed for S256 method")
	}
}

func TestTailscaleIDP_ValidateRedirectURI(t *testing.T) {
	idp := NewTailscaleIDP(
		"https://issuer.com",
		"client-123",
		"secret-456",
		[]string{"https://app.com/callback", "http://localhost:8080/callback"},
	)

	// Valid redirects
	if err := idp.ValidateRedirectURI("https://app.com/callback"); err != nil {
		t.Errorf("expected no error for valid redirect URI, got: %v", err)
	}
	if err := idp.ValidateRedirectURI("http://localhost:8080/callback"); err != nil {
		t.Errorf("expected no error for localhost redirect URI, got: %v", err)
	}

	// Invalid redirect
	if err := idp.ValidateRedirectURI("https://attacker.com/callback"); err == nil {
		t.Error("expected error for attacker redirect URI, but got nil")
	}
}

func TestTailscaleIDP_GenerateClaims(t *testing.T) {
	idp := NewTailscaleIDP("https://issuer.com", "client-123", "secret-456", []string{"https://app.com/callback"})
	claims := idp.GenerateClaims(
		"sub-100",
		"alice",
		"alice@net.com",
		"tailnet-456",
		"node-xyz",
		[]string{"100.64.0.1"},
	)

	if claims.Subject != "sub-100" || claims.Username != "alice" || claims.Tailnet != "tailnet-456" {
		t.Errorf("claims constructed incorrectly: %+v", claims)
	}
}

func TestTailscaleIDP_FlattenExtraClaims(t *testing.T) {
	idp := NewTailscaleIDP("https://issuer.com", "client-123", "secret-456", []string{"https://app.com/callback"})
	base := map[string]interface{}{
		"sub": "sub-123",
		"custom-key": "val1",
	}
	extra := map[string]interface{}{
		"sub": "overwrite-attempt-sub",
		"extra-key": "val2",
	}
	flat := idp.FlattenExtraClaims(base, extra)
	if flat["sub"] != "sub-123" {
		t.Errorf("Protected claim 'sub' was overwritten: got %v", flat["sub"])
	}
	if flat["custom-key"] != "val1" || flat["extra-key"] != "val2" {
		t.Errorf("Claims flattening failed: %+v", flat)
	}
}

func TestTailscaleIDP_Capabilities(t *testing.T) {
	idp := NewTailscaleIDP("https://issuer.com", "client-123", "secret-456", []string{"https://app.com/callback"})
	capJSON := `{"cap/admin": {"ports": [80, 443]}}`
	caps, err := idp.UnmarshalCapabilities(capJSON)
	if err != nil {
		t.Errorf("UnmarshalCapabilities failed: %v", err)
	}
	if caps["cap/admin"] == nil {
		t.Error("Expected capability mapping not found")
	}
}

func TestTailscaleIDP_ServeOpenIDConfig(t *testing.T) {
	idp := NewTailscaleIDP("https://issuer.com", "client-123", "secret-456", []string{"https://app.com/callback"})

	// Test OPTIONS preflight
	reqOptions := httptest.NewRequest("OPTIONS", "/.well-known/openid-configuration", nil)
	rrOptions := httptest.NewRecorder()
	idp.ServeOpenIDConfig(rrOptions, reqOptions)
	if rrOptions.Code != http.StatusNoContent {
		t.Errorf("Expected status 204 for OPTIONS, got %d", rrOptions.Code)
	}
	if rrOptions.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("Missing Access-Control-Allow-Origin header")
	}

	// Test GET metadata
	reqGet := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	rrGet := httptest.NewRecorder()
	idp.ServeOpenIDConfig(rrGet, reqGet)
	if rrGet.Code != http.StatusOK {
		t.Errorf("Expected status 200 for GET, got %d", rrGet.Code)
	}
	var meta OpenIDProviderMetadata
	if err := json.Unmarshal(rrGet.Body.Bytes(), &meta); err != nil {
		t.Errorf("Failed to parse metadata JSON: %v", err)
	}
	if meta.Issuer != "https://issuer.com" {
		t.Errorf("Expected issuer https://issuer.com, got %s", meta.Issuer)
	}
}

func TestTailscaleIDP_ServeUserInfo(t *testing.T) {
	idp := NewTailscaleIDP("https://issuer.com", "client-123", "secret-456", []string{"https://app.com/callback"})
	claims := idp.GenerateClaims("sub-alice", "alice", "alice@domain.com", "tailnet-1", "node-1", []string{"100.64.0.5"})
	token := "token-valid-abc"

	idp.ActiveTokens[token] = &TokenSession{
		Token:     token,
		Claims:    claims,
		ValidTill: time.Now().Add(10 * time.Minute),
		IsTagged:  false,
	}

	// Unauthenticated
	reqUnauth := httptest.NewRequest("GET", "/userinfo", nil)
	rrUnauth := httptest.NewRecorder()
	idp.ServeUserInfo(rrUnauth, reqUnauth)
	if rrUnauth.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 411/401 for unauthenticated request, got %d", rrUnauth.Code)
	}

	// Authenticated
	reqAuth := httptest.NewRequest("GET", "/userinfo", nil)
	reqAuth.Header.Set("Authorization", "Bearer token-valid-abc")
	rrAuth := httptest.NewRecorder()
	idp.ServeUserInfo(rrAuth, reqAuth)
	if rrAuth.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", rrAuth.Code, rrAuth.Body.String())
	}
	var uinfo TailscaleUserInfo
	if err := json.Unmarshal(rrAuth.Body.Bytes(), &uinfo); err != nil {
		t.Errorf("Failed to parse userinfo JSON: %v", err)
	}
	if uinfo.Sub != "sub-alice" || uinfo.Name != "alice" {
		t.Errorf("UserInfo claims mismatch: %+v", uinfo)
	}
}
