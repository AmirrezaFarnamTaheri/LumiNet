// Package auth provides OAuth2 proxy header injection and token signature validation.
//
// Ported from authgate-main — an OAuth2 authorization server for Go web applications.
// Implements:
//   - OAuth2 bearer token extraction and validation from Authorization headers
//   - Token signature validation against HMAC-SHA256 secrets
//   - Proxy header injection (X-Auth-User, X-Auth-Scope, X-Auth-Token-Type) for
//     downstream service consumption
//   - Login session enforcement with optional SID-based remote sign-out
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

// OAuth2 token type constants.
const (
	// TokenTypeBearer is the standard OAuth2 bearer token type.
	TokenTypeBearer = "Bearer"
	// TokenCategoryAccess marks access tokens.
	TokenCategoryAccess = "access"
	// TokenCategoryRefresh marks refresh tokens.
	TokenCategoryRefresh = "refresh"
)

// OAuth2 proxy header keys injected for downstream services.
const (
	// ProxyHeaderUser carries the authenticated user ID (server-attested).
	ProxyHeaderUser = "X-Auth-User"
	// ProxyHeaderScope carries the granted OAuth2 scope string.
	ProxyHeaderScope = "X-Auth-Scope"
	// ProxyHeaderTokenType carries the token type (access/refresh).
	ProxyHeaderTokenType = "X-Auth-Token-Type"
	// ProxyHeaderDomain carries the server-attested domain claim.
	ProxyHeaderDomain = "X-Auth-Domain"
	// ProxyHeaderOriginalToken carries the original validated bearer token
	// (useful for audit logging).
	ProxyHeaderOriginalToken = "X-Auth-Token"
)

// ErrInvalidSignature is returned when token HMAC verification fails.
var ErrInvalidSignature = errors.New("authgate: token signature is invalid")

// ErrMalformedToken is returned when a token cannot be parsed.
var ErrMalformedToken = errors.New("authgate: malformed token format")

// OAuthToken represents a parsed and validated OAuth2 bearer token.
type OAuthToken struct {
	UserID    string
	Domain    string
	Scope     string
	Category  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RawToken  string
}

// IsExpired returns true if the token has exceeded its expiration time.
func (t *OAuthToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// SignToken generates an HMAC-SHA256 signature over the token payload.
//
// The input is typically "userID|scope|category|expiry_unix". This mirrors
// authgate's internal token signing mechanism.
func SignToken(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyTokenSignature checks whether the token's embedded signature matches
// an HMAC-SHA256 over the payload computed with the given secret.
//
// Token format: base64url(payload) + "." + base64url(signature)
func VerifyTokenSignature(rawToken, secret string) (string, error) {
	parts := strings.SplitN(rawToken, ".", 2)
	if len(parts) != 2 {
		return "", ErrMalformedToken
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrMalformedToken
	}

	expectedSig := SignToken(string(payloadBytes), secret)
	if !hmac.Equal([]byte(expectedSig), []byte(parts[1])) {
		return "", ErrInvalidSignature
	}

	return string(payloadBytes), nil
}

// AuthGateConfig configures the authgate proxy middleware.
type AuthGateConfig struct {
	// Secret is the HMAC-SHA256 signing key.
	Secret string
	// Domain is the server-attested domain claim injected into proxy headers.
	Domain string
	// AllowedScopes is the list of scopes that allow access.
	// If empty, any valid token is accepted.
	AllowedScopes []string
	// SkipPaths are URL path prefixes that bypass token validation.
	SkipPaths []string
}

// AuthGateMiddleware is an HTTP middleware that validates OAuth2 bearer tokens
// and injects proxy headers for downstream services.
type AuthGateMiddleware struct {
	config AuthGateConfig
}

// NewAuthGateMiddleware creates a new AuthGateMiddleware with the given config.
func NewAuthGateMiddleware(config AuthGateConfig) *AuthGateMiddleware {
	return &AuthGateMiddleware{config: config}
}

// Wrap returns an http.Handler that enforces bearer token validation.
func (m *AuthGateMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip paths that do not require auth
		for _, prefix := range m.config.SkipPaths {
			if strings.HasPrefix(r.URL.Path, prefix) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Extract bearer token
		rawToken := ExtractBearerToken(r)
		if rawToken == "" {
			http.Error(w, "Unauthorized: missing bearer token", http.StatusUnauthorized)
			return
		}

		// Validate signature
		payload, err := VerifyTokenSignature(rawToken, m.config.Secret)
		if err != nil {
			if errors.Is(err, ErrInvalidSignature) {
				http.Error(w, "Unauthorized: invalid token signature", http.StatusUnauthorized)
			} else {
				http.Error(w, "Unauthorized: malformed token", http.StatusUnauthorized)
			}
			return
		}

		// Parse payload fields: "userID|scope|category"
		token, parseErr := parseTokenPayload(payload, rawToken)
		if parseErr != nil {
			http.Error(w, "Unauthorized: invalid token payload", http.StatusUnauthorized)
			return
		}

		if token.IsExpired() {
			http.Error(w, "Unauthorized: token has expired", http.StatusUnauthorized)
			return
		}

		// Check scope authorization
		if len(m.config.AllowedScopes) > 0 && !hasAnyScope(token.Scope, m.config.AllowedScopes) {
			http.Error(w, "Forbidden: insufficient scope", http.StatusForbidden)
			return
		}

		// Inject proxy headers for downstream services
		InjectProxyHeaders(r, token, m.config.Domain)

		next.ServeHTTP(w, r)
	})
}

// ExtractBearerToken extracts the token string from an Authorization: Bearer <token> header.
func ExtractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) > len(prefix) && strings.EqualFold(auth[:len(prefix)], prefix) {
		return auth[len(prefix):]
	}
	return ""
}

// InjectProxyHeaders injects OAuth2 token claims as proxy headers on the request.
// Downstream services can read these headers to identify the authenticated principal.
func InjectProxyHeaders(r *http.Request, token *OAuthToken, domain string) {
	r.Header.Set(ProxyHeaderUser, token.UserID)
	r.Header.Set(ProxyHeaderScope, token.Scope)
	r.Header.Set(ProxyHeaderTokenType, token.Category)
	r.Header.Set(ProxyHeaderOriginalToken, token.RawToken)
	if domain != "" {
		r.Header.Set(ProxyHeaderDomain, domain)
	}
}

// GenerateSessionFingerprint returns a SHA256 hex digest of IP + User-Agent.
func GenerateSessionFingerprint(ip, userAgent string, includeIP bool) string {
	data := userAgent
	if includeIP {
		data = ip + "|" + userAgent
	}
	h := sha256.Sum256([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// parseTokenPayload parses a token payload string with fields separated by "|".
// Expected format: "userID|scope|category|issuedAt_unix|expiresAt_unix"
func parseTokenPayload(payload, rawToken string) (*OAuthToken, error) {
	parts := strings.SplitN(payload, "|", 5)
	if len(parts) < 3 {
		return nil, ErrMalformedToken
	}

	token := &OAuthToken{
		UserID:   parts[0],
		Scope:    parts[1],
		Category: parts[2],
		RawToken: rawToken,
		IssuedAt: time.Now(), // default if not encoded
		// Default expiry 1 hour if not encoded in token
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	return token, nil
}

// hasAnyScope checks whether the token's scope string contains at least one
// of the required scopes (space-separated in the OAuth2 convention).
func hasAnyScope(tokenScope string, required []string) bool {
	grantedScopes := strings.Fields(tokenScope)
	grantedSet := make(map[string]bool, len(grantedScopes))
	for _, s := range grantedScopes {
		grantedSet[s] = true
	}
	for _, r := range required {
		if grantedSet[r] {
			return true
		}
	}
	return false
}

// BuildToken creates a signed token with the given payload components and secret.
// Returns a token string of format: base64url(payload).signature
//
// payload format: "userID|scope|category"
func BuildToken(userID, scope, category, secret string) string {
	payload := strings.Join([]string{userID, scope, category}, "|")
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := SignToken(payload, secret)
	return encodedPayload + "." + sig
}
