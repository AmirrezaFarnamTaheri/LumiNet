// Package auth handles authentication, identity, and OpenID Connect tokens validation.
// Ported from: tsidp-main
// Target path: server/internal/auth/tailscale_idp.go

package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TailscaleClaims holds Tailscale OpenID Connect Identity Provider claims.
type TailscaleClaims struct {
	Subject   string   `json:"sub"`
	Issuer    string   `json:"iss"`
	Audience  string   `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	Key       string   `json:"key"`
	Addresses []string `json:"addresses"`
	Node      string   `json:"node"`
	Tailnet   string   `json:"tailnet"`
	UID       string   `json:"uid"`
}

// TailscaleUserInfo represents the OIDC UserInfo endpoint profile response.
type TailscaleUserInfo struct {
	Sub       string   `json:"sub"`
	Name      string   `json:"name"`
	Email     string   `json:"email"`
	Addresses []string `json:"addresses,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// OpenIDProviderMetadata represents the OIDC discovery configuration parameters.
type OpenIDProviderMetadata struct {
	Issuer                                string   `json:"issuer"`
	AuthorizationEndpoint                 string   `json:"authorization_endpoint"`
	TokenEndpoint                         string   `json:"token_endpoint"`
	UserinfoEndpoint                      string   `json:"userinfo_endpoint"`
	JwksURI                               string   `json:"jwks_uri"`
	ScopesSupported                       []string `json:"scopes_supported"`
	ResponseTypesSupported                []string `json:"response_types_supported"`
	SubjectTypesSupported                 []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported      []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported     []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                       []string `json:"claims_supported"`
	CodeChallengeMethodsSupported         []string `json:"code_challenge_methods_supported"`
}

// TailscaleIDP handles Tailscale identity provision and OIDC client registry.
type TailscaleIDP struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	ActiveTokens map[string]*TokenSession
}

type TokenSession struct {
	Token      string
	Claims     *TailscaleClaims
	ValidTill  time.Time
	CapRules   map[string]interface{}
	IsTagged   bool
}

// NewTailscaleIDP creates a new Tailscale IDP auth manager.
func NewTailscaleIDP(issuerURL string, clientID string, clientSecret string, redirects []string) *TailscaleIDP {
	return &TailscaleIDP{
		IssuerURL:    issuerURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: redirects,
		ActiveTokens: make(map[string]*TokenSession),
	}
}

// VerifyPKCE validates PKCE code challenges against verifiers (RFC 7636).
func (t *TailscaleIDP) VerifyPKCE(codeVerifier string, codeChallenge string, method string) bool {
	if method == "" || strings.ToLower(method) == "plain" {
		return codeVerifier == codeChallenge
	}
	if strings.ToLower(method) == "s256" {
		h := sha256.New()
		h.Write([]byte(codeVerifier))
		hashed := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
		return hashed == codeChallenge
	}
	return false
}

// FlattenExtraClaims combines and deduplicates claims.
func (t *TailscaleIDP) FlattenExtraClaims(base map[string]interface{}, extra map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{})
	for k, v := range base {
		out[k] = v
	}
	protected := map[string]bool{
		"sub": true, "iss": true, "aud": true, "exp": true, "iat": true,
	}
	for k, v := range extra {
		if protected[k] {
			continue // Skip protected claims
		}
		out[k] = v
	}
	return out
}

// UnmarshalCapabilities parses Capabilities JSON payload.
func (t *TailscaleIDP) UnmarshalCapabilities(capJSON string) (map[string]interface{}, error) {
	var caps map[string]interface{}
	if err := json.Unmarshal([]byte(capJSON), &caps); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cap JSON: %w", err)
	}
	return caps, nil
}

// GenerateClaims constructs Tailscale identity provider OIDC client auth claims.
func (t *TailscaleIDP) GenerateClaims(
	sub string,
	username string,
	email string,
	tailnet string,
	node string,
	ips []string,
) *TailscaleClaims {
	now := time.Now()
	return &TailscaleClaims{
		Subject:   sub,
		Issuer:    t.IssuerURL,
		Audience:  t.ClientID,
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
		IssuedAt:  now.Unix(),
		Username:  username,
		Email:     email,
		Key:       fmt.Sprintf("nodekey:%s", sub),
		Addresses: ips,
		Node:      node,
		Tailnet:   tailnet,
		UID:       fmt.Sprintf("ts-uid-%s", sub),
	}
}

// ValidateRedirectURI checks if the requested redirect URI is registered.
func (t *TailscaleIDP) ValidateRedirectURI(redirectURI string) error {
	parsedRequest, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect URI format: %w", err)
	}

	for _, registered := range t.RedirectURIs {
		parsedReg, err := url.Parse(registered)
		if err != nil {
			continue
		}
		if parsedRequest.Scheme == parsedReg.Scheme &&
			parsedRequest.Host == parsedReg.Host &&
			parsedRequest.Path == parsedReg.Path {
			return nil
		}
	}

	return errors.New("redirect URI not registered")
}

// ServeOpenIDConfig handles discovery config route query with CORS wildcard settings.
func (t *TailscaleIDP) ServeOpenIDConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	metadata := OpenIDProviderMetadata{
		Issuer:                            t.IssuerURL,
		AuthorizationEndpoint:             t.IssuerURL + "/oauth/authorize",
		TokenEndpoint:                     t.IssuerURL + "/oauth/token",
		UserinfoEndpoint:                  t.IssuerURL + "/userinfo",
		JwksURI:                           t.IssuerURL + "/jwks",
		ScopesSupported:                   []string{"openid", "profile", "email"},
		ResponseTypesSupported:            []string{"code", "id_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
		ClaimsSupported:                   []string{"sub", "aud", "exp", "iat", "iss", "name", "email", "addresses", "tags"},
		CodeChallengeMethodsSupported:     []string{"plain", "S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// ServeUserInfo verifies token, cleans expired entries and returns user profile values.
func (t *TailscaleIDP) ServeUserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		t.writeBearerError(w, "invalid_token", "Missing or malformed Authorization header")
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Expired sessions cleanup
	now := time.Now()
	for k, v := range t.ActiveTokens {
		if v.ValidTill.Before(now) {
			delete(t.ActiveTokens, k)
		}
	}

	session, ok := t.ActiveTokens[token]
	if !ok {
		t.writeBearerError(w, "invalid_token", "Active token session not found")
		return
	}

	if session.IsTagged {
		t.writeBearerError(w, "forbidden", "Access denied: Node is tagged")
		return
	}

	userinfo := TailscaleUserInfo{
		Sub:       session.Claims.Subject,
		Name:      session.Claims.Username,
		Email:     session.Claims.Email,
		Addresses: session.Claims.Addresses,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(userinfo)
}

func (t *TailscaleIDP) writeBearerError(w http.ResponseWriter, errCode string, description string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", error_description="%s"`, errCode, description))
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"error": "%s", "error_description": "%s"}`, errCode, description)))
}
