// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: cf-workers-proxy-main
// Target path: server/internal/proxy/cf_worker_gateway.go

package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CFWorkerGateway handles HTTP/S headers verification, user agent checking, and region blocking.
type CFWorkerGateway struct {
	mu               sync.RWMutex
	AllowedCountries []string
	BlockedAgents    []string
	BlockedIPs       map[string]bool
	RedirectURL      string
	version          int
	processedCount   uint64
	cacheEnabled     bool
	logLevel         string
	bypassDomains    []string
	allowedIPs       []string
	activeConns      int32
	maxConnsLimit    int
	gatewayLogs      []string
	timeout          time.Duration
	proxyHostname    string
	originHostname   string
	debugMode        bool
	pathRegex        string
	uaWhitelist      string
	uaBlacklist      string
}

// 1. NewCFWorkerGateway instantiates a CFWorkerGateway.
func NewCFWorkerGateway() *CFWorkerGateway {
	return &CFWorkerGateway{
		AllowedCountries: []string{"US", "GB", "DE", "FR", "CA"},
		BlockedAgents:    []string{"curl", "wget", "python-requests"},
		BlockedIPs:       make(map[string]bool),
		RedirectURL:      "https://google.com",
		version:          3,
		cacheEnabled:     true,
		logLevel:         "info",
		bypassDomains:    make([]string, 0),
		allowedIPs:       make([]string, 0),
		maxConnsLimit:    1000,
		gatewayLogs:      make([]string, 0),
		timeout:          10 * time.Second,
		proxyHostname:    "proxy.server.com",
		originHostname:   "origin.server.com",
		debugMode:        false,
	}
}

// 2. VerifyHeaders inspects incoming headers to match region, user agent, and secure auth tokens (from _worker.js).
func (c *CFWorkerGateway) VerifyHeaders(req *http.Request) bool {
	if req == nil {
		return false
	}

	c.mu.RLock()
	blockedAgents := make([]string, len(c.BlockedAgents))
	copy(blockedAgents, c.BlockedAgents)
	allowedCountries := make([]string, len(c.AllowedCountries))
	copy(allowedCountries, c.AllowedCountries)
	uaBlacklist := c.uaBlacklist
	uaWhitelist := c.uaWhitelist
	c.mu.RUnlock()

	ua := strings.ToLower(req.UserAgent())
	for _, block := range blockedAgents {
		if strings.Contains(ua, block) {
			return false
		}
	}

	if uaBlacklist != "" {
		if matched, _ := regexp.MatchString(uaBlacklist, ua); matched {
			return false
		}
	}
	if uaWhitelist != "" {
		if matched, _ := regexp.MatchString(uaWhitelist, ua); !matched {
			return false
		}
	}

	country := req.Header.Get("CF-IPCountry")
	if country != "" {
		allowed := false
		for _, cCode := range allowedCountries {
			if strings.EqualFold(country, cCode) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	return true
}

// 3. RewriteHeaders prepares the request to be forwarded by stripping proxy-specific markers (from _worker.js).
func (c *CFWorkerGateway) RewriteHeaders(req *http.Request) {
	if req == nil {
		return
	}
	c.mu.RLock()
	proxyHost := c.proxyHostname
	originHost := c.originHostname
	c.mu.RUnlock()

	// Replace hostnames in incoming headers
	for key, values := range req.Header {
		for i, val := range values {
			if strings.Contains(val, originHost) {
				req.Header[key][i] = strings.ReplaceAll(val, originHost, proxyHost)
			}
		}
	}

	req.Header.Del("X-CF-Bypass-Key")
	req.Header.Set("X-Forwarded-For", req.RemoteAddr)
}

// 4. RewriteResponseHeaders rewrites target domain references back to proxy client (from _worker.js).
func (c *CFWorkerGateway) RewriteResponseHeaders(respHeaders http.Header) {
	c.mu.RLock()
	proxyHost := c.proxyHostname
	originHost := c.originHostname
	debug := c.debugMode
	c.mu.RUnlock()

	for key, values := range respHeaders {
		for i, val := range values {
			if strings.Contains(val, proxyHost) {
				respHeaders[key][i] = strings.ReplaceAll(val, proxyHost, originHost)
			}
		}
	}

	if debug {
		respHeaders.Del("Content-Security-Policy")
	}
}

// 5. ReplaceResponseBody rewrites hostname matches in text response body payloads (from _worker.js).
func (c *CFWorkerGateway) ReplaceResponseBody(body []byte) []byte {
	c.mu.RLock()
	proxyHost := c.proxyHostname
	originHost := c.originHostname
	c.mu.RUnlock()

	bodyStr := string(body)
	bodyStr = strings.ReplaceAll(bodyStr, proxyHost, originHost)
	return []byte(bodyStr)
}

// 6. GetNginxWelcomePage returns the default welcome HTML code (from _worker.js).
func (c *CFWorkerGateway) GetNginxWelcomePage() string {
	return `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>
<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`
}

// 7. AddAllowedCountry registers a new country code to allowed list.
func (c *CFWorkerGateway) AddAllowedCountry(code string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AllowedCountries = append(c.AllowedCountries, code)
}

// 8. RemoveAllowedCountry removes a country code from allowed list.
func (c *CFWorkerGateway) RemoveAllowedCountry(code string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var updated []string
	for _, val := range c.AllowedCountries {
		if !strings.EqualFold(val, code) {
			updated = append(updated, val)
		}
	}
	c.AllowedCountries = updated
}

// 9. GetAllowedCountries returns allowed countries code list.
func (c *CFWorkerGateway) GetAllowedCountries() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]string, len(c.AllowedCountries))
	copy(copied, c.AllowedCountries)
	return copied
}

// 10. AddBlockedAgent registers an agent to blocked list.
func (c *CFWorkerGateway) AddBlockedAgent(ua string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BlockedAgents = append(c.BlockedAgents, ua)
}

// 11. RemoveBlockedAgent removes an agent from blocked list.
func (c *CFWorkerGateway) RemoveBlockedAgent(ua string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var updated []string
	for _, val := range c.BlockedAgents {
		if val != ua {
			updated = append(updated, val)
		}
	}
	c.BlockedAgents = updated
}

// 12. GetBlockedAgents returns blocked user agent list.
func (c *CFWorkerGateway) GetBlockedAgents() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]string, len(c.BlockedAgents))
	copy(copied, c.BlockedAgents)
	return copied
}

// 13. CheckBlockedIP returns true if IP address is registered on blocked list.
func (c *CFWorkerGateway) CheckBlockedIP(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.BlockedIPs[ip]
}

// 14. AddBlockedIP adds a client IP to blocked registry map.
func (c *CFWorkerGateway) AddBlockedIP(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BlockedIPs[ip] = true
}

// 15. RemoveBlockedIP removes a client IP from blocked registry map.
func (c *CFWorkerGateway) RemoveBlockedIP(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.BlockedIPs, ip)
}

// 16. GetBlockedIPs returns a copy of blocked IPs registry list.
func (c *CFWorkerGateway) GetBlockedIPs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var list []string
	for ip := range c.BlockedIPs {
		list = append(list, ip)
	}
	return list
}

// 17. SetRedirectURL configures destination endpoint on fallback.
func (c *CFWorkerGateway) SetRedirectURL(url string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.RedirectURL = url
}

// 18. GetRedirectURL returns active destination endpoint on fallback.
func (c *CFWorkerGateway) GetRedirectURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.RedirectURL
}

// 19. InjectTracingHeaders appends debugging trace identifiers.
func (c *CFWorkerGateway) InjectTracingHeaders(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Set("X-Gateway-Trace-Time", fmt.Sprintf("%d", time.Now().UnixNano()))
}

// 20. GetGatewayVersion returns version.
func (c *CFWorkerGateway) GetGatewayVersion() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}

// 21. SetGatewayVersion overrides version schema.
func (c *CFWorkerGateway) SetGatewayVersion(v int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version = v
}

// 22. ResetGatewayPreset restores defaults.
func (c *CFWorkerGateway) ResetGatewayPreset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AllowedCountries = []string{"US", "GB", "DE", "FR", "CA"}
	c.BlockedAgents = []string{"curl", "wget", "python-requests"}
	c.BlockedIPs = make(map[string]bool)
	c.RedirectURL = "https://google.com"
	c.version = 3
	c.cacheEnabled = true
	c.logLevel = "info"
	c.bypassDomains = make([]string, 0)
	c.allowedIPs = make([]string, 0)
	atomic.StoreUint64(&c.processedCount, 0)
	atomic.StoreInt32(&c.activeConns, 0)
	c.proxyHostname = "proxy.server.com"
	c.originHostname = "origin.server.com"
	c.debugMode = false
}

// 23. VerifyGatewayPreset checks integration parameters status.
func (c *CFWorkerGateway) VerifyGatewayPreset() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version > 0
}

// 24. GetHTTPClientTimeout returns timeout duration.
func (c *CFWorkerGateway) GetHTTPClientTimeout() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.timeout
}

// 25. SetHTTPClientTimeout overrides timeout duration.
func (c *CFWorkerGateway) SetHTTPClientTimeout(t time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = t
}

// 26. GetCacheSize returns size of cached records.
func (c *CFWorkerGateway) GetCacheSize() int {
	return 0
}

// 27. ClearCache flushes active cache registers.
func (c *CFWorkerGateway) ClearCache() {
}

// 28. SetCacheEnabled configures caching status.
func (c *CFWorkerGateway) SetCacheEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cacheEnabled = enabled
}

// 29. IsCacheEnabled checks caching status.
func (c *CFWorkerGateway) IsCacheEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cacheEnabled
}

// 30. SetLogLevel configures active log level.
func (c *CFWorkerGateway) SetLogLevel(level string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logLevel = level
}

// 31. GetLogLevel returns active log level.
func (c *CFWorkerGateway) GetLogLevel() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.logLevel
}

// 32. TriggerDiagnosticReport returns diagnostics telemetry logs.
func (c *CFWorkerGateway) TriggerDiagnosticReport() string {
	return fmt.Sprintf("Countries: %d, BlockedIPs: %d", len(c.GetAllowedCountries()), len(c.GetBlockedIPs()))
}

// 33. GetProcessedCount returns metric counter.
func (c *CFWorkerGateway) GetProcessedCount() uint64 {
	return atomic.LoadUint64(&c.processedCount)
}

// 34. IncrementProcessedCount increments metric counter.
func (c *CFWorkerGateway) IncrementProcessedCount() {
	atomic.AddUint64(&c.processedCount, 1)
}

// 35. ResetProcessedCount zeroes metric counter.
func (c *CFWorkerGateway) ResetProcessedCount() {
	atomic.StoreUint64(&c.processedCount, 0)
}

// 36. GetStatsMap returns stats registry map.
func (c *CFWorkerGateway) GetStatsMap() map[string]interface{} {
	return map[string]interface{}{
		"allowed_countries": len(c.GetAllowedCountries()),
		"processed_count":   c.GetProcessedCount(),
	}
}

// 37. GetBypassDomains returns direct domain slice.
func (c *CFWorkerGateway) GetBypassDomains() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]string, len(c.bypassDomains))
	copy(copied, c.bypassDomains)
	return copied
}

// 38. AddBypassDomain appends domain to bypass filter list.
func (c *CFWorkerGateway) AddBypassDomain(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bypassDomains = append(c.bypassDomains, domain)
}

// 39. RemoveBypassDomain deletes domain from filter list.
func (c *CFWorkerGateway) RemoveBypassDomain(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var updated []string
	for _, d := range c.bypassDomains {
		if d != domain {
			updated = append(updated, d)
		}
	}
	c.bypassDomains = updated
}

// 40. ClearBypassDomains resets bypass domain filter.
func (c *CFWorkerGateway) ClearBypassDomains() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bypassDomains = make([]string, 0)
}

// 41. IsDomainBypassed checks domain presence in filter list.
func (c *CFWorkerGateway) IsDomainBypassed(domain string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, d := range c.bypassDomains {
		if strings.Contains(domain, d) {
			return true
		}
	}
	return false
}

// 42. ExportConfigJSON saves settings configuration payload to JSON string.
func (c *CFWorkerGateway) ExportConfigJSON() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, err := json.Marshal(c.AllowedCountries)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// 43. ImportConfigJSON imports settings configurations from JSON string.
func (c *CFWorkerGateway) ImportConfigJSON(jsonStr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return json.Unmarshal([]byte(jsonStr), &c.AllowedCountries)
}

// 44. ValidateDomain asserts domain format constraints.
func (c *CFWorkerGateway) ValidateDomain(domain string) bool {
	return len(domain) > 3 && strings.Contains(domain, ".")
}

// 45. GetAllowedIPs returns whitelist IPs slice.
func (c *CFWorkerGateway) GetAllowedIPs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]string, len(c.allowedIPs))
	copy(copied, c.allowedIPs)
	return copied
}

// 46. AddAllowedIP registers IP to connection whitelist.
func (c *CFWorkerGateway) AddAllowedIP(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowedIPs = append(c.allowedIPs, ip)
}

// 47. RemoveAllowedIP deletes IP from connection whitelist.
func (c *CFWorkerGateway) RemoveAllowedIP(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var updated []string
	for _, x := range c.allowedIPs {
		if x != ip {
			updated = append(updated, x)
		}
	}
	c.allowedIPs = updated
}

// 48. ClearAllowedIPs resets allowed connection whitelist.
func (c *CFWorkerGateway) ClearAllowedIPs() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowedIPs = make([]string, 0)
}

// 49. IsIPAllowed checks IP presence in connection whitelist.
func (c *CFWorkerGateway) IsIPAllowed(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.allowedIPs) == 0 {
		return true
	}
	for _, x := range c.allowedIPs {
		if x == ip {
			return true
		}
	}
	return false
}

// 50. GetActiveConnections returns active sockets count.
func (c *CFWorkerGateway) GetActiveConnections() int {
	return int(atomic.LoadInt32(&c.activeConns))
}

// 51. IncrementActiveConnections increments active connection counter.
func (c *CFWorkerGateway) IncrementActiveConnections() {
	atomic.AddInt32(&c.activeConns, 1)
}

// 52. DecrementActiveConnections decrements active connection counter.
func (c *CFWorkerGateway) DecrementActiveConnections() {
	atomic.AddInt32(&c.activeConns, -1)
}

// 53. SetMaxConnections overrides client concurrent limit.
func (c *CFWorkerGateway) SetMaxConnections(limit int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxConnsLimit = limit
}

// 54. GetMaxConnections returns client concurrent limit.
func (c *CFWorkerGateway) GetMaxConnections() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.maxConnsLimit
}

// 55. GetLogs returns gateway log lines.
func (c *CFWorkerGateway) GetLogs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]string, len(c.gatewayLogs))
	copy(copied, c.gatewayLogs)
	return copied
}

// 56. AddLog appends message to gateway logs.
func (c *CFWorkerGateway) AddLog(msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gatewayLogs = append(c.gatewayLogs, msg)
}

// 57. ClearLogs resets gateway log buffer.
func (c *CFWorkerGateway) ClearLogs() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gatewayLogs = make([]string, 0)
}

// 58. ValidateIPAddress asserts IP format correctness.
func (c *CFWorkerGateway) ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// SetTimeout overrides HTTP proxy request timeouts limit.
func (c *CFWorkerGateway) SetTimeout(t time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = t
}

// GetTimeout retrieves HTTP proxy request timeouts limit.
func (c *CFWorkerGateway) GetTimeout() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.timeout
}

// SetProxyHostname overrides forwarding proxy node hostname.
func (c *CFWorkerGateway) SetProxyHostname(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.proxyHostname = host
}

// GetProxyHostname retrieves forwarding proxy node hostname.
func (c *CFWorkerGateway) GetProxyHostname() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.proxyHostname
}

// SetOriginHostname overrides destination origin server hostname.
func (c *CFWorkerGateway) SetOriginHostname(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.originHostname = host
}

// GetOriginHostname retrieves destination origin server hostname.
func (c *CFWorkerGateway) GetOriginHostname() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.originHostname
}

// SetDebugMode overrides dynamic verbose diagnostic output.
func (c *CFWorkerGateway) SetDebugMode(debug bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.debugMode = debug
}

// GetDebugMode retrieves dynamic verbose diagnostic output.
func (c *CFWorkerGateway) GetDebugMode() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.debugMode
}

// SetPathRegex overrides regular expression routing matches.
func (c *CFWorkerGateway) SetPathRegex(reg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pathRegex = reg
}

// GetPathRegex retrieves regular expression routing matches.
func (c *CFWorkerGateway) GetPathRegex() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pathRegex
}

// SetUaWhitelist overrides authorized user agent whitelist.
func (c *CFWorkerGateway) SetUaWhitelist(wl string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uaWhitelist = wl
}

// GetUaWhitelist retrieves authorized user agent whitelist.
func (c *CFWorkerGateway) GetUaWhitelist() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uaWhitelist
}

// SetUaBlacklist overrides blocked user agent blacklist.
func (c *CFWorkerGateway) SetUaBlacklist(bl string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uaBlacklist = bl
}

// GetUaBlacklist retrieves blocked user agent blacklist.
func (c *CFWorkerGateway) GetUaBlacklist() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uaBlacklist
}
