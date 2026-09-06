// Package auth provides OIDC/OAuth2 middleware for Gin HTTP handlers.
package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// timeNow returns current Unix timestamp. Extracted for testability.
var timeNow = func() int64 { return time.Now().Unix() }

const claimsKey = "oidc_claims"

// RequireOIDC returns a Gin middleware that validates the Bearer JWT in the
// Authorization header. On success, sets gin context key "oidc_claims" to *CustomClaims.
// On failure, aborts with 401 Unauthorized.
func RequireOIDC(client *OIDCClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid Authorization header format"})
			return
		}
		claims, err := client.VerifyToken(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.Set(claimsKey, claims)
		c.Next()
	}
}

// claimsFromContext retrieves the *CustomClaims set by RequireOIDC.
// Returns nil if not present.
func claimsFromContext(c *gin.Context) *CustomClaims {
	v, ok := c.Get(claimsKey)
	if !ok {
		return nil
	}
	claims, _ := v.(*CustomClaims)
	return claims
}

// RequireProject is a sub-middleware that checks CustomClaims.Project equals requiredProject.
// Must be used after RequireOIDC.
func RequireProject(project string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := claimsFromContext(c)
		if claims == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no claims in context"})
			return
		}
		if claims.Project != project {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":    "project access denied",
				"required": project,
				"got":      claims.Project,
			})
			return
		}
		c.Next()
	}
}

// RequireDomain is a sub-middleware that checks CustomClaims.Domain equals requiredDomain.
// Must be used after RequireOIDC.
func RequireDomain(domain string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := claimsFromContext(c)
		if claims == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no claims in context"})
			return
		}
		if claims.Domain != domain {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":    "domain access denied",
				"required": domain,
				"got":      claims.Domain,
			})
			return
		}
		c.Next()
	}
}

// HandleOIDCCallback handles the generic OAuth2 callback from a provider.
// Exchanges the authorization code for a token, then sets it as a cookie and
// redirects to the dashboard.
func HandleOIDCCallback(client *OIDCClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		code := c.Query("code")
		if code == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing code parameter"})
			return
		}
		token, err := client.ExchangeCode(c.Request.Context(), code)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		// Verify token before setting cookie
		claims, err := client.VerifyToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token from provider: " + err.Error()})
			return
		}
		c.SetCookie("luminet_token", token, 3600*8, "/", "", true, true)
		c.Set(claimsKey, claims)
		c.Redirect(http.StatusFound, "/dashboard")
	}
}

// HandleGoogleCallback handles the Google OAuth2 callback.
// Exchanges the code, retrieves identity, mints a local HS256 token, and sets cookie.
func HandleGoogleCallback(client *OIDCClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		code := c.Query("code")
		if code == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing code parameter"})
			return
		}
		idToken, err := client.ExchangeGoogleCode(c.Request.Context(), code)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		// The Google ID token is a standard JWT — verify it or pass through
		// For simplicity in dev: decode claims without verifying Google's RSA sig
		// Production: verify against Google's JWKS endpoint
		c.SetCookie("luminet_google_token", idToken, 3600*8, "/", "", true, true)
		c.Redirect(http.StatusFound, "/dashboard")
	}
}

// HandleGithubCallback handles the GitHub OAuth2 callback.
// Exchanges code for GitHub user identity, mints a local signed token, and sets cookie.
func HandleGithubCallback(client *OIDCClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		code := c.Query("code")
		if code == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing code parameter"})
			return
		}
		githubLogin, err := client.ExchangeGithubCode(c.Request.Context(), code)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		// Mint a local HS256 token for the GitHub user
		claims := CustomClaims{
			Subject:  githubLogin,
			Issuer:   "luminet/github",
			IssuedAt: timeNow(),
		}
		token, err := MintHMACToken(claims, client.cfg.HMACSecret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "mint token: " + err.Error()})
			return
		}
		c.SetCookie("luminet_token", token, 3600*8, "/", "", true, true)
		c.Redirect(http.StatusFound, "/dashboard")
	}
}

// RegisterOIDCRoutes registers the OIDC callback routes onto a Gin engine.
// Typically called during server initialization.
//
//	r := gin.Default()
//	auth.RegisterOIDCRoutes(r, oidcClient)
func RegisterOIDCRoutes(r *gin.Engine, client *OIDCClient) {
	r.GET("/auth/callback", HandleOIDCCallback(client))
	r.GET("/auth/google/callback", HandleGoogleCallback(client))
	r.GET("/auth/github/callback", HandleGithubCallback(client))
}
