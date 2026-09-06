// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: cloudflare-bypass-main
// Target path: server/internal/proxy/cf_bypass.go

package proxy

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CFBypass handles Cloudflare Worker header wrapping and request bypass mimicry.
type CFBypass struct {
	mu           sync.RWMutex
	PresharedKey string
	UserAgent    string
}

// NewCFBypass instantiates a new CFBypass helper.
func NewCFBypass(key string) *CFBypass {
	return &CFBypass{
		PresharedKey: key,
		UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}
}

// 1. WrapRequest injects custom headers, bypass authentication, and browser headers.
func (c *CFBypass) WrapRequest(req *http.Request) {
	if req == nil {
		return
	}
	c.mu.RLock()
	ua := c.UserAgent
	key := c.PresharedKey
	c.mu.RUnlock()

	req.Header.Set("User-Agent", ua)
	req.Header.Set("X-CF-Bypass-Key", key)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
}

// 2. SetPresharedKey configures the authentication key.
func (c *CFBypass) SetPresharedKey(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.PresharedKey = key
}

// 3. GetPresharedKey returns the authentication key.
func (c *CFBypass) GetPresharedKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.PresharedKey
}

// 4. SetUserAgent configures a custom user agent.
func (c *CFBypass) SetUserAgent(ua string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UserAgent = ua
}

// 5. GetUserAgent returns the active user agent.
func (c *CFBypass) GetUserAgent() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UserAgent
}

// 6. GenerateRandomUserAgent rotates browser header payloads.
func (c *CFBypass) GenerateRandomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(agents))))
	if err != nil {
		return agents[0]
	}
	return agents[n.Int64()]
}

// 7. WrapResponse scrubs Cloudflare fingerprints from headers.
func (c *CFBypass) WrapResponse(w http.ResponseWriter) {
	w.Header().Del("CF-RAY")
	w.Header().Del("cf-request-id")
	w.Header().Set("Server", "nginx")
}

// 8. IsCloudflareBlocked detects if a response indicates blocking.
func (c *CFBypass) IsCloudflareBlocked(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusForbidden {
		if strings.Contains(resp.Header.Get("Server"), "cloudflare") {
			return true
		}
	}
	return false
}

// 9. CheckBypassAuth checks incoming auth keys.
func (c *CFBypass) CheckBypassAuth(req *http.Request) bool {
	if req == nil {
		return false
	}
	c.mu.RLock()
	key := c.PresharedKey
	c.mu.RUnlock()
	return req.Header.Get("X-CF-Bypass-Key") == key
}

// 10. AddBypassCookie appends obfuscated session cookies.
func (c *CFBypass) AddBypassCookie(req *http.Request, name, value string) {
	if req == nil {
		return
	}
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	req.AddCookie(cookie)
}

// 11. RemoveTrackingHeaders removes debugging headers.
func (c *CFBypass) RemoveTrackingHeaders(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Real-IP")
}

// 12. AddCacheBuster adds timestamp parameters to URL queries.
func (c *CFBypass) AddCacheBuster(req *http.Request) {
	if req == nil || req.URL == nil {
		return
	}
	q := req.URL.Query()
	q.Set("_cb", fmt.Sprintf("%d", time.Now().UnixNano()))
	req.URL.RawQuery = q.Encode()
}

// 13. InjectAJ3Signature injects client JA3 fingerprint parameters.
func (c *CFBypass) InjectAJ3Signature(req *http.Request, signature string) {
	if req == nil {
		return
	}
	req.Header.Set("X-JA3-Signature", signature)
}

// 14. ConfigureALPN sets client protocol tags.
func (c *CFBypass) ConfigureALPN(req *http.Request, alpn string) {
	if req == nil {
		return
	}
	req.Header.Set("X-ALPN-Negotiation", alpn)
}

// 15. Bypass is the diagnostic trigger function.
func (c *CFBypass) Bypass() {
	// Diagnostic stub
}
