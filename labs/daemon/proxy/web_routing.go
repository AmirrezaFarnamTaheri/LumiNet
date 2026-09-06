// Package proxy implements proxy URI parsing, testing, subscription management,
// and core instance lifecycle for various proxy protocols.
package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/geoip"
)

// ClashRuleType represents the type of Clash/Mihomo rule.
type ClashRuleType string

const (
	RuleTypeDomain        ClashRuleType = "DOMAIN"
	RuleTypeDomainSuffix  ClashRuleType = "DOMAIN-SUFFIX"
	RuleTypeDomainKeyword ClashRuleType = "DOMAIN-KEYWORD"
	RuleTypeGeoIP         ClashRuleType = "GEOIP"
	RuleTypeIPCidr        ClashRuleType = "IP-CIDR"
	RuleTypeSrcIPCidr     ClashRuleType = "SRC-IP-CIDR"
	RuleTypeProcessName   ClashRuleType = "PROCESS-NAME"
	RuleTypeMatch         ClashRuleType = "MATCH"
)

// ClashRule defines a single parsed Clash routing rule.
type ClashRule struct {
	Type        ClashRuleType `json:"type"`
	Payload     string        `json:"payload"`
	OutboundTag string        `json:"outbound_tag"`
	IPNet       *net.IPNet    `json:"-"`
}

// ClashMetaRouter handles Mihomo (Clash.Meta) routing rules evaluation.
type ClashMetaRouter struct {
	mu           sync.RWMutex
	Rules        []ClashRule
	GeoIPService *geoip.Service
	dnsCache     sync.Map
}

// NewClashMetaRouter creates a new ClashMetaRouter instance.
func NewClashMetaRouter(geoipDbPath string) (*ClashMetaRouter, error) {
	svc, err := geoip.NewService(geoipDbPath)
	if err != nil {
		return nil, err
	}
	return &ClashMetaRouter{
		GeoIPService: svc,
	}, nil
}

// ClearDNSCache flushes the routing DNS cache.
func (r *ClashMetaRouter) ClearDNSCache() {
	r.dnsCache.Range(func(key, value interface{}) bool {
		r.dnsCache.Delete(key)
		return true
	})
	slog.Info("Clash router DNS cache cleared successfully to prevent DNS leak tracking")
}

// AddRules parses and appends new routing rules.
func (r *ClashMetaRouter) AddRules(ruleStrings []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var newRules []ClashRule
	for _, ruleStr := range ruleStrings {
		parts := strings.Split(ruleStr, ",")
		if len(parts) < 2 {
			continue
		}

		t := ClashRuleType(strings.ToUpper(strings.TrimSpace(parts[0])))
		var payload, tag string

		if t == RuleTypeMatch {
			tag = strings.TrimSpace(parts[1])
		} else if len(parts) >= 3 {
			payload = strings.TrimSpace(parts[1])
			tag = strings.TrimSpace(parts[2])
		} else {
			continue
		}

		rule := ClashRule{
			Type:        t,
			Payload:     payload,
			OutboundTag: tag,
		}

		if t == RuleTypeIPCidr || t == RuleTypeSrcIPCidr {
			_, ipNet, err := net.ParseCIDR(payload)
			if err == nil {
				rule.IPNet = ipNet
			}
		}

		newRules = append(newRules, rule)
	}

	r.Rules = newRules
	r.ClearDNSCache()
	return nil
}

// MatchOutbound evaluates host, destination IP, source IP, and process targets against Clash routing rules.
func (r *ClashMetaRouter) MatchOutbound(host string, destIP net.IP, srcIP net.IP, processName string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	lowerHost := strings.ToLower(host)

	for _, rule := range r.Rules {
		switch rule.Type {
		case RuleTypeDomain:
			if lowerHost == strings.ToLower(rule.Payload) {
				return rule.OutboundTag
			}
		case RuleTypeDomainSuffix:
			if strings.HasSuffix(lowerHost, strings.ToLower(rule.Payload)) {
				return rule.OutboundTag
			}
		case RuleTypeDomainKeyword:
			if strings.Contains(lowerHost, strings.ToLower(rule.Payload)) {
				return rule.OutboundTag
			}
		case RuleTypeIPCidr:
			if destIP != nil && rule.IPNet != nil {
				if rule.IPNet.Contains(destIP) {
					return rule.OutboundTag
				}
			}
		case RuleTypeSrcIPCidr:
			if srcIP != nil && rule.IPNet != nil {
				if rule.IPNet.Contains(srcIP) {
					return rule.OutboundTag
				}
			}
		case RuleTypeGeoIP:
			if destIP != nil {
				// Query country code using geoip Service
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_, code, _, _, _, _, err := r.GeoIPService.Lookup(ctx, destIP.String())
				cancel()
				if err == nil && strings.EqualFold(code, rule.Payload) {
					return rule.OutboundTag
				}
			}
		case RuleTypeProcessName:
			if processName != "" && strings.EqualFold(processName, rule.Payload) {
				return rule.OutboundTag
			}
		case RuleTypeMatch:
			return rule.OutboundTag
		}
	}

	return "DIRECT" // Default fallback outbound tag
}

// ProviderConfigLoader handles periodic configuration updates from remote subscription sources.
type ProviderConfigLoader struct {
	mu         sync.Mutex
	providers  map[string]*ProviderSource
	httpClient *http.Client
	router     *ClashMetaRouter
}

// ProviderSource represents a single managed provider subscription source.
type ProviderSource struct {
	Name     string
	URL      string
	Interval time.Duration
	stopChan chan struct{}
}

// NewProviderConfigLoader initializes a ProviderConfigLoader.
func NewProviderConfigLoader(router *ClashMetaRouter) *ProviderConfigLoader {
	return &ProviderConfigLoader{
		providers: make(map[string]*ProviderSource),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		router: router,
	}
}

// AddProvider registers and schedules a remote config source provider.
func (l *ProviderConfigLoader) AddProvider(name string, url string, interval time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Stop existing provider if it has the same name
	if old, exists := l.providers[name]; exists {
		close(old.stopChan)
	}

	stopChan := make(chan struct{})
	p := &ProviderSource{
		Name:     name,
		URL:      url,
		Interval: interval,
		stopChan: stopChan,
	}
	l.providers[name] = p

	go l.runUpdateLoop(p)
}

// StopAll stops all periodic configuration source updates.
func (l *ProviderConfigLoader) StopAll() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, p := range l.providers {
		close(p.stopChan)
	}
	l.providers = make(map[string]*ProviderSource)
}

func (l *ProviderConfigLoader) runUpdateLoop(p *ProviderSource) {
	ticker := time.NewTicker(p.Interval)
	defer ticker.Stop()

	// Trigger initial update immediately
	l.triggerUpdate(p)

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			l.triggerUpdate(p)
		}
	}
}

func (l *ProviderConfigLoader) triggerUpdate(p *ProviderSource) {
	log.Printf("Triggering provider config source update for: %s", p.Name)
	resp, err := l.httpClient.Get(p.URL)
	if err != nil {
		log.Printf("Provider %s fetch failed: %v", p.Name, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Provider %s fetch returned status code: %d", p.Name, resp.StatusCode)
		return
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Provider %s body read failed: %v", p.Name, err)
		return
	}

	// Dynamic update of routing configuration rules
	var rulesContainer struct {
		Rules []string `yaml:"rules"`
	}

	// Simple parser or unmarshaler (yaml/json) depending on header content-type
	if strings.Contains(resp.Header.Get("Content-Type"), "yaml") || strings.HasSuffix(p.URL, ".yaml") {
		// Mock parse rules from yaml string blocks
		lines := strings.Split(string(data), "\n")
		var extractedRules []string
		inRulesBlock := false
		for _, line := range lines {
			lineTrimmed := strings.TrimSpace(line)
			if lineTrimmed == "rules:" {
				inRulesBlock = true
				continue
			}
			if inRulesBlock {
				if strings.HasPrefix(lineTrimmed, "-") {
					extractedRules = append(extractedRules, strings.TrimPrefix(lineTrimmed, "- "))
				} else if lineTrimmed != "" && !strings.Contains(lineTrimmed, ":") {
					extractedRules = append(extractedRules, lineTrimmed)
				} else if strings.Contains(lineTrimmed, ":") {
					break
				}
			}
		}
		rulesContainer.Rules = extractedRules
	} else {
		_ = json.Unmarshal(data, &rulesContainer)
	}

	if len(rulesContainer.Rules) > 0 {
		_ = l.router.AddRules(rulesContainer.Rules)
		log.Printf("Provider %s updated: %d rules loaded and DNS cache cleared", p.Name, len(rulesContainer.Rules))
	}
}

// TokenAuthMiddleware verifies API token auth credentials.
func TokenAuthMiddleware(secretToken string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if secretToken == "" {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		token := c.Query("token")

		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && parts[0] == "Bearer" {
				token = parts[1]
			}
		}

		if token != secretToken {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized: invalid secret token parameters",
			})
			return
		}
		c.Next()
	}
}

// RegisterDashboardRoutes configures web routing for local Yacd/Metacubexd dashboards and APIs.
func RegisterDashboardRoutes(router *gin.Engine, staticDir string, secretToken string, clashRouter *ClashMetaRouter) {
	// API Group with token authentication audit safety
	api := router.Group("/api/v1")
	api.Use(TokenAuthMiddleware(secretToken))
	{
		api.GET("/rules", func(c *gin.Context) {
			clashRouter.mu.RLock()
			defer clashRouter.mu.RUnlock()
			c.JSON(http.StatusOK, gin.H{
				"rules": clashRouter.Rules,
			})
		})

		api.POST("/rules", func(c *gin.Context) {
			var req struct {
				Rules []string `json:"rules"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			if err := clashRouter.AddRules(req.Rules); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Rules updated successfully"})
		})

		api.POST("/dns/flush", func(c *gin.Context) {
			clashRouter.ClearDNSCache()
			c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "DNS cache flushed"})
		})
	}

	// Serve Static Dashboard files
	if _, err := os.Stat(staticDir); err == nil {
		router.StaticFS("/dashboard", http.Dir(staticDir))
		router.GET("/", func(c *gin.Context) {
			c.Redirect(http.StatusMovedPermanently, "/dashboard")
		})
		log.Printf("Serving local Yacd/Metacubexd dashboard console from: %s at /dashboard", staticDir)
	} else {
		// Mock default console index response if directory is missing
		router.GET("/dashboard", func(c *gin.Context) {
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(`
				<!DOCTYPE html>
				<html>
				<head>
					<title>LumiNet Metacubexd Console Mock</title>
					<style>
						body { font-family: sans-serif; background: #121212; color: #ffffff; padding: 40px; text-align: center; }
						.box { border: 1px solid #333; padding: 20px; border-radius: 8px; max-width: 500px; margin: 40px auto; background: #1e1e1e; }
					</style>
				</head>
				<body>
					<div class="box">
						<h2>LumiNet Metacubexd Console Mock</h2>
						<p>Standard static UI console mock. REST API is active under <code>/api/v1/</code>.</p>
					</div>
				</body>
				</html>
			`))
		})
	}
}

// CamouflageMiddleware returns a GIN middleware that intercepts requests.
// If the request pathname does NOT start with any of the allowed prefixes,
// and a camouflage directory exists, it serves static files from that directory.
func CamouflageMiddleware(camouflageDir string, allowedPrefixes []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Check if path starts with any allowed prefix
		isAllowed := false
		for _, prefix := range allowedPrefixes {
			if strings.HasPrefix(path, prefix) {
				isAllowed = true
				break
			}
		}

		if isAllowed {
			c.Next()
			return
		}

		// If camouflage directory does not exist or is empty, serve a generic 404
		if _, err := os.Stat(camouflageDir); err != nil {
			c.Data(http.StatusNotFound, "text/html; charset=utf-8", []byte(`
				<!DOCTYPE html>
				<html>
				<head><title>Not Found</title></head>
				<body><h2>HTTP 404 - Not Found</h2></body>
				</html>
			`))
			c.Abort()
			return
		}

		// Serve static file using Gin's built-in file server
		http.FileServer(http.Dir(camouflageDir)).ServeHTTP(c.Writer, c.Request)
		c.Abort()
	}
}

// RateLimitedReader wraps an io.Reader and limits read speed using a token bucket.
type RateLimitedReader struct {
	R      io.Reader
	Limit  int64 // bytes per second
	mu     sync.Mutex
	tokens int64
	last   time.Time
}

// NewRateLimitedReader creates a new RateLimitedReader instance.
func NewRateLimitedReader(r io.Reader, limitBps int64) *RateLimitedReader {
	return &RateLimitedReader{
		R:     r,
		Limit: limitBps,
		last:  time.Now(),
	}
}

func (rlr *RateLimitedReader) Read(p []byte) (n int, err error) {
	if rlr.Limit <= 0 {
		return rlr.R.Read(p)
	}

	rlr.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(rlr.last).Seconds()
	rlr.last = now

	// Refill tokens
	rlr.tokens += int64(elapsed * float64(rlr.Limit))
	if rlr.tokens > rlr.Limit {
		rlr.tokens = rlr.Limit
	}

	// Calculate maximum we can read right now
	maxRead := int64(len(p))
	if maxRead > rlr.tokens {
		maxRead = rlr.tokens
	}

	rlr.mu.Unlock()

	// If no tokens, sleep/wait
	if maxRead <= 0 {
		sleepTime := time.Duration(50 * time.Millisecond)
		time.Sleep(sleepTime)
		return rlr.Read(p)
	}

	n, err = rlr.R.Read(p[:maxRead])

	rlr.mu.Lock()
	rlr.tokens -= int64(n)
	rlr.mu.Unlock()

	return n, err
}

// RateLimitedWriter wraps an io.Writer and limits write speed using a token bucket.
type RateLimitedWriter struct {
	W      io.Writer
	Limit  int64 // bytes per second
	mu     sync.Mutex
	tokens int64
	last   time.Time
}

// NewRateLimitedWriter creates a new RateLimitedWriter instance.
func NewRateLimitedWriter(w io.Writer, limitBps int64) *RateLimitedWriter {
	return &RateLimitedWriter{
		W:     w,
		Limit: limitBps,
		last:  time.Now(),
	}
}

func (rlw *RateLimitedWriter) Write(p []byte) (n int, err error) {
	if rlw.Limit <= 0 {
		return rlw.W.Write(p)
	}

	written := 0
	for written < len(p) {
		rlw.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(rlw.last).Seconds()
		rlw.last = now

		// Refill tokens
		rlw.tokens += int64(elapsed * float64(rlw.Limit))
		if rlw.tokens > rlw.Limit {
			rlw.tokens = rlw.Limit
		}

		// Calculate how much we can write in this chunk
		chunk := int64(len(p) - written)
		if chunk > rlw.tokens {
			chunk = rlw.tokens
		}
		rlw.mu.Unlock()

		if chunk <= 0 {
			time.Sleep(20 * time.Millisecond)
			continue
		}

		nWritten, err := rlw.W.Write(p[written : written+int(chunk)])
		if err != nil {
			return written + nWritten, err
		}

		rlw.mu.Lock()
		rlw.tokens -= int64(nWritten)
		rlw.mu.Unlock()

		written += nWritten
	}

	return written, nil
}
