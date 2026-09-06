// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Cloudflare-Workers-Proxy-main
// Target path: server/internal/proxy/cloudflare_workers_proxy.go

package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CloudflareWorkersProxy manages relative HTML rewrites, headers cleaning, and CORS setups (from worker.js).
type CloudflareWorkersProxy struct {
	mu                sync.RWMutex
	corsMethods       string
	corsHeaders       string
	noCacheVal        string
	connsCount        int64
	version           int
	allowedDomains    []string
	blockedUserAgents []string
	requestTimeout    time.Duration
	responseSizeLimit int64
	logLevel          string
	logCount          uint64
	customHeaders     map[string]string
	cookiesRewriteMap map[string]string
}

// NewCloudflareWorkersProxy initializes a new CloudflareWorkersProxy.
func NewCloudflareWorkersProxy() *CloudflareWorkersProxy {
	return &CloudflareWorkersProxy{
		corsMethods:       "GET,POST,OPTIONS,PUT,DELETE",
		corsHeaders:       "Content-Type,Authorization,X-Requested-With",
		noCacheVal:        "no-store, no-cache, must-revalidate, max-age=0",
		version:           1,
		allowedDomains:    make([]string, 0),
		blockedUserAgents: make([]string, 0),
		requestTimeout:    10 * time.Second,
		responseSizeLimit: 10 * 1024 * 1024,
		logLevel:          "info",
		customHeaders:     make(map[string]string),
		cookiesRewriteMap: make(map[string]string),
	}
}

// CleanHeaders filters out cf- prefixed headers (from worker.js).
func (c *CloudflareWorkersProxy) CleanHeaders(input http.Header) http.Header {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cleaned := make(http.Header)
	for name, values := range input {
		if !strings.HasPrefix(strings.ToLower(name), "cf-") {
			cleaned[name] = values
		}
	}
	return cleaned
}

// SetCorsAndCacheHeaders sets headers to enable cross-origin requests and disable local caches (from worker.js).
func (c *CloudflareWorkersProxy) SetCorsAndCacheHeaders(w http.ResponseWriter) {
	c.mu.RLock()
	methods := c.corsMethods
	headers := c.corsHeaders
	noCache := c.noCacheVal
	c.mu.RUnlock()

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", methods)
	w.Header().Set("Access-Control-Allow-Headers", headers)
	w.Header().Set("Cache-Control", noCache)
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

// RewriteHtmlContent replaces relative href/src/action tags with proxy paths (from worker.js).
func (c *CloudflareWorkersProxy) RewriteHtmlContent(htmlContent string, host string) string {
	// Replaces href="/relative" with href="/https%3A%2F%2Fhost%2Frelative"
	re := regexp.MustCompile(`((href|src|action)=["'])/(?!/)`)
	replacement := fmt.Sprintf(`$1/https://%s/`, host)
	return re.ReplaceAllString(htmlContent, replacement)
}

// HandleRedirectLocation constructs proxy redirection URL parameters (from worker.js).
func (c *CloudflareWorkersProxy) HandleRedirectLocation(locationStr string) string {
	escaped := url.QueryEscape(locationStr)
	return fmt.Sprintf("/%s", escaped)
}

// SetCorsMethods overrides CORS Access-Control-Allow-Methods header parameters.
func (c *CloudflareWorkersProxy) SetCorsMethods(methods string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.corsMethods = methods
}

// GetCorsMethods retrieves CORS Access-Control-Allow-Methods header parameters.
func (c *CloudflareWorkersProxy) GetCorsMethods() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.corsMethods
}

// SetCorsHeaders overrides CORS Access-Control-Allow-Headers header parameters.
func (c *CloudflareWorkersProxy) SetCorsHeaders(headers string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.corsHeaders = headers
}

// GetCorsHeaders retrieves CORS Access-Control-Allow-Headers header parameters.
func (c *CloudflareWorkersProxy) GetCorsHeaders() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.corsHeaders
}

// SetNoCacheVal overrides CORS Cache-Control header parameters.
func (c *CloudflareWorkersProxy) SetNoCacheVal(val string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noCacheVal = val
}

// GetNoCacheVal retrieves CORS Cache-Control header parameters.
func (c *CloudflareWorkersProxy) GetNoCacheVal() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.noCacheVal
}

// SetConnsCount overrides concurrent connection logs counter.
func (c *CloudflareWorkersProxy) SetConnsCount(val int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connsCount = val
}

// GetConnsCount retrieves concurrent connection logs counter.
func (c *CloudflareWorkersProxy) GetConnsCount() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connsCount
}

// SetVersion overrides configuration schema version.
func (c *CloudflareWorkersProxy) SetVersion(v int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version = v
}

// GetVersion retrieves configuration schema version.
func (c *CloudflareWorkersProxy) GetVersion() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}

// SetAllowedDomains overrides whitelist of request forwarding domains.
func (c *CloudflareWorkersProxy) SetAllowedDomains(domains []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make([]string, len(domains))
	copy(copied, domains)
	c.allowedDomains = copied
}

// GetAllowedDomains retrieves whitelist of request forwarding domains.
func (c *CloudflareWorkersProxy) GetAllowedDomains() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]string, len(c.allowedDomains))
	copy(copied, c.allowedDomains)
	return copied
}

// AddAllowedDomain registers a new domain to forward whitelist.
func (c *CloudflareWorkersProxy) AddAllowedDomain(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowedDomains = append(c.allowedDomains, domain)
}

// RemoveAllowedDomain deletes domain from forward whitelist.
func (c *CloudflareWorkersProxy) RemoveAllowedDomain(domain string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := -1
	for i, d := range c.allowedDomains {
		if d == domain {
			idx = i
			break
		}
	}
	if idx != -1 {
		c.allowedDomains = append(c.allowedDomains[:idx], c.allowedDomains[idx+1:]...)
		return true
	}
	return false
}

// ClearAllowedDomains flushes allowed domains whitelist.
func (c *CloudflareWorkersProxy) ClearAllowedDomains() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowedDomains = make([]string, 0)
}

// GetAllowedDomainsCount retrieves count of active allowed domains.
func (c *CloudflareWorkersProxy) GetAllowedDomainsCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.allowedDomains)
}

// SetBlockedUserAgents overrides blacklist of user agents.
func (c *CloudflareWorkersProxy) SetBlockedUserAgents(agents []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make([]string, len(agents))
	copy(copied, agents)
	c.blockedUserAgents = copied
}

// GetBlockedUserAgents retrieves blacklist of user agents.
func (c *CloudflareWorkersProxy) GetBlockedUserAgents() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]string, len(c.blockedUserAgents))
	copy(copied, c.blockedUserAgents)
	return copied
}

// AddBlockedUserAgent registers user agent to blacklist.
func (c *CloudflareWorkersProxy) AddBlockedUserAgent(agent string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockedUserAgents = append(c.blockedUserAgents, agent)
}

// RemoveBlockedUserAgent deletes user agent from blacklist.
func (c *CloudflareWorkersProxy) RemoveBlockedUserAgent(agent string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := -1
	for i, a := range c.blockedUserAgents {
		if a == agent {
			idx = i
			break
		}
	}
	if idx != -1 {
		c.blockedUserAgents = append(c.blockedUserAgents[:idx], c.blockedUserAgents[idx+1:]...)
		return true
	}
	return false
}

// ClearBlockedUserAgents flushes user agents blacklist.
func (c *CloudflareWorkersProxy) ClearBlockedUserAgents() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockedUserAgents = make([]string, 0)
}

// GetBlockedUserAgentsCount retrieves count of active blacklisted agents.
func (c *CloudflareWorkersProxy) GetBlockedUserAgentsCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.blockedUserAgents)
}

// SetRequestTimeout overrides HTTP client connection timeout limit.
func (c *CloudflareWorkersProxy) SetRequestTimeout(t time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestTimeout = t
}

// GetRequestTimeout retrieves HTTP client connection timeout limit.
func (c *CloudflareWorkersProxy) GetRequestTimeout() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.requestTimeout
}

// SetResponseSizeLimit overrides response buffer memory bounds.
func (c *CloudflareWorkersProxy) SetResponseSizeLimit(limit int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responseSizeLimit = limit
}

// GetResponseSizeLimit retrieves response buffer memory bounds.
func (c *CloudflareWorkersProxy) GetResponseSizeLimit() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.responseSizeLimit
}

// SetLogLevel overrides diagnostic output log details level.
func (c *CloudflareWorkersProxy) SetLogLevel(level string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logLevel = level
}

// GetLogLevel retrieves diagnostic output log details level.
func (c *CloudflareWorkersProxy) GetLogLevel() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.logLevel
}

// SetLogCount overrides total written log statements.
func (c *CloudflareWorkersProxy) SetLogCount(val uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logCount = val
}

// GetLogCount retrieves total written log statements.
func (c *CloudflareWorkersProxy) GetLogCount() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.logCount
}

// SetCustomHeaders overrides HTTP client request injected headers map.
func (c *CloudflareWorkersProxy) SetCustomHeaders(headers map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make(map[string]string)
	for k, v := range headers {
		copied[k] = v
	}
	c.customHeaders = copied
}

// GetCustomHeaders retrieves HTTP client request injected headers map.
func (c *CloudflareWorkersProxy) GetCustomHeaders() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make(map[string]string)
	for k, v := range c.customHeaders {
		copied[k] = v
	}
	return copied
}

// AddCustomHeader registers key-value to request injected headers.
func (c *CloudflareWorkersProxy) AddCustomHeader(key, val string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.customHeaders[key] = val
}

// RemoveCustomHeader deletes injected custom header.
func (c *CloudflareWorkersProxy) RemoveCustomHeader(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, exists := c.customHeaders[key]
	if exists {
		delete(c.customHeaders, key)
	}
	return exists
}

// ClearCustomHeaders flushes custom headers map.
func (c *CloudflareWorkersProxy) ClearCustomHeaders() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.customHeaders = make(map[string]string)
}

// GetCustomHeadersCount retrieves count of active injected headers.
func (c *CloudflareWorkersProxy) GetCustomHeadersCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.customHeaders)
}

// SetCookiesRewriteMap overrides mapping of cookie names to rewrite.
func (c *CloudflareWorkersProxy) SetCookiesRewriteMap(m map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	copied := make(map[string]string)
	for k, v := range m {
		copied[k] = v
	}
	c.cookiesRewriteMap = copied
}

// GetCookiesRewriteMap retrieves mapping of cookie names to rewrite.
func (c *CloudflareWorkersProxy) GetCookiesRewriteMap() map[string]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make(map[string]string)
	for k, v := range c.cookiesRewriteMap {
		copied[k] = v
	}
	return copied
}
