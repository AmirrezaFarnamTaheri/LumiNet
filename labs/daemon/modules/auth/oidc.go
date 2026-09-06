// Package auth provides OIDC/OAuth2 JWT verification and social login integration
// for the LumiNet admin dashboard.
//
// Decision: Use external IdP with standard OAuth2 client
//
// Target: server/internal/auth/oidc.go
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CustomClaims holds OIDC JWT claims including LumiNet private namespace claims.
// Private claims are prefixed with "extra_" following standard conventions.
type CustomClaims struct {
	// Standard JWT registered claims (RFC 7519)
	Subject   string `json:"sub"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti,omitempty"`

	// LumiNet private namespace claims
	Domain         string `json:"extra_domain,omitempty"`
	Project        string `json:"extra_project,omitempty"`
	ServiceAccount string `json:"extra_service_account,omitempty"`
}

// OIDCConfig holds all configuration for OIDC provider integration.
type OIDCConfig struct {
	// Generic OIDC
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	HMACSecret   []byte // For HS256 token verification

	// Google OAuth2
	GoogleClientID string
	GoogleSecret   string
	GoogleRedirect string

	// GitHub OAuth2
	GithubClientID string
	GithubSecret   string
	GithubRedirect string
}

// OIDCClient manages OIDC provider discovery, token exchange, and JWT verification.
type OIDCClient struct {
	cfg    OIDCConfig
	client *http.Client
}

// NewOIDCClient creates a new OIDC client with the given configuration.
func NewOIDCClient(cfg OIDCConfig) *OIDCClient {
	return &OIDCClient{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// AuthCodeURL returns the authorization redirect URL for the configured OIDC provider.
// The state parameter is used to prevent CSRF attacks.
func (c *OIDCClient) AuthCodeURL(state string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.cfg.ClientID)
	params.Set("redirect_uri", c.cfg.RedirectURL)
	params.Set("state", state)
	if len(c.cfg.Scopes) > 0 {
		params.Set("scope", strings.Join(c.cfg.Scopes, " "))
	} else {
		params.Set("scope", "openid profile email")
	}
	return c.cfg.Issuer + "/authorize?" + params.Encode()
}

// ExchangeCode exchanges an authorization code for a JWT token string.
// Returns the raw JWT access or id_token.
func (c *OIDCClient) ExchangeCode(ctx context.Context, code string) (string, error) {
	tokenURL := c.cfg.Issuer + "/token"
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", code)
	params.Set("redirect_uri", c.cfg.RedirectURL)
	params.Set("client_id", c.cfg.ClientID)
	params.Set("client_secret", c.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return "", fmt.Errorf("oidc: create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc: token exchange: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("oidc: read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc: token exchange failed (%d): %s", resp.StatusCode, body)
	}

	var result struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("oidc: parse token response: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("oidc: provider error %q: %s", result.Error, result.ErrorDesc)
	}
	if result.IDToken != "" {
		return result.IDToken, nil
	}
	return result.AccessToken, nil
}

// VerifyToken verifies a HS256-signed JWT and returns the parsed claims.
// Validates: signature, expiry, issuer (if configured).
func (c *OIDCClient) VerifyToken(tokenString string) (*CustomClaims, error) {
	parts := strings.Split(strings.TrimSpace(tokenString), ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: malformed JWT: expected 3 parts")
	}

	// Verify the header declares HS256
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: decode JWT header: %w", err)
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("oidc: parse JWT header: %w", err)
	}
	if header.Algorithm != "HS256" {
		return nil, fmt.Errorf("oidc: unexpected signing algorithm %q, expected HS256", header.Algorithm)
	}

	// Verify HMAC-SHA256 signature over header.payload
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, c.cfg.HMACSecret)
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: decode JWT signature: %w", err)
	}
	if !hmac.Equal(expectedSig, gotSig) {
		return nil, errors.New("oidc: signature verification failed")
	}

	// Decode and parse claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: decode JWT claims: %w", err)
	}
	var claims CustomClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("oidc: parse JWT claims: %w", err)
	}

	// Validate expiry
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, fmt.Errorf("oidc: token expired at %d (now %d)", claims.ExpiresAt, now)
	}

	// Validate issuer if configured
	if c.cfg.Issuer != "" && claims.Issuer != "" && claims.Issuer != c.cfg.Issuer {
		return nil, fmt.Errorf("oidc: issuer mismatch: got %q, want %q", claims.Issuer, c.cfg.Issuer)
	}

	return &claims, nil
}

// ─── Google OAuth2 ────────────────────────────────────────────────────────────

const googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
const googleTokenURL = "https://oauth2.googleapis.com/token"

// GoogleAuthURL returns the Google OAuth2 authorization redirect URL.
func (c *OIDCClient) GoogleAuthURL(state string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.cfg.GoogleClientID)
	params.Set("redirect_uri", c.cfg.GoogleRedirect)
	params.Set("scope", "openid email profile")
	params.Set("state", state)
	params.Set("access_type", "offline")
	return googleAuthURL + "?" + params.Encode()
}

// ExchangeGoogleCode exchanges a Google authorization code for an id_token.
func (c *OIDCClient) ExchangeGoogleCode(ctx context.Context, code string) (string, error) {
	params := url.Values{}
	params.Set("code", code)
	params.Set("client_id", c.cfg.GoogleClientID)
	params.Set("client_secret", c.cfg.GoogleSecret)
	params.Set("redirect_uri", c.cfg.GoogleRedirect)
	params.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("google: token exchange: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("google: token exchange failed (%d): %s", resp.StatusCode, body)
	}

	var result struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	if result.Error != "" {
		return "", fmt.Errorf("google: %s", result.Error)
	}
	return result.IDToken, nil
}

// ─── GitHub OAuth2 ────────────────────────────────────────────────────────────

const githubAuthURL  = "https://github.com/login/oauth/authorize"
const githubTokenURL = "https://github.com/login/oauth/access_token"
const githubUserURL  = "https://api.github.com/user"

// GithubAuthURL returns the GitHub OAuth2 authorization redirect URL.
func (c *OIDCClient) GithubAuthURL(state string) string {
	params := url.Values{}
	params.Set("client_id", c.cfg.GithubClientID)
	params.Set("redirect_uri", c.cfg.GithubRedirect)
	params.Set("scope", "read:user user:email")
	params.Set("state", state)
	return githubAuthURL + "?" + params.Encode()
}

// ExchangeGithubCode exchanges a GitHub authorization code for a user email string.
// GitHub does not issue JWTs; this returns the authenticated user's login as the subject.
func (c *OIDCClient) ExchangeGithubCode(ctx context.Context, code string) (string, error) {
	params := url.Values{}
	params.Set("client_id", c.cfg.GithubClientID)
	params.Set("client_secret", c.cfg.GithubSecret)
	params.Set("code", code)
	params.Set("redirect_uri", c.cfg.GithubRedirect)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: token exchange: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github: token exchange failed (%d): %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Error != "" {
		return "", fmt.Errorf("github: %s", tokenResp.Error)
	}

	// Fetch user identity from GitHub API
	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, githubUserURL, nil)
	if err != nil {
		return "", err
	}
	userReq.Header.Set("Authorization", "token "+tokenResp.AccessToken)
	userReq.Header.Set("Accept", "application/vnd.github.v3+json")

	userResp, err := c.client.Do(userReq)
	if err != nil {
		return "", fmt.Errorf("github: fetch user: %w", err)
	}
	defer userResp.Body.Close()
	userBody, _ := io.ReadAll(io.LimitReader(userResp.Body, 16*1024))

	var user struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(userBody, &user); err != nil {
		return "", err
	}
	// Return GitHub login as the identity subject
	return user.Login, nil
}

// MintHMACToken creates a signed HS256 JWT for the given claims.
// Useful for issuing tokens in tests or local dev without a real IdP.
func MintHMACToken(claims CustomClaims, secret []byte) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := header + "." + payload

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}
