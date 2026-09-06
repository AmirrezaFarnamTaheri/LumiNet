// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: F0rc3Run-panel
// Target path: server/internal/proxy/forcerun.go

package proxy

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ForcerunPipeline manages the automated CI/CD pipeline logic to continuously scrape,
// encode, and dynamically publish multi-protocol proxy subscriptions.
type ForcerunPipeline struct {
	mu             sync.RWMutex
	sources        []string
	httpClient     *http.Client
	version        int
	processedCount uint64
	cacheEnabled   bool
	logLevel       string
	bypassDomains  []string
	allowedIPs     []string
	activeConns    int32
	maxConnsLimit  int
	pipelineLogs   []string
}

// NewForcerunPipeline initializes the pipeline.
func NewForcerunPipeline(sources []string) *ForcerunPipeline {
	return &ForcerunPipeline{
		sources: sources,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		version:       1,
		cacheEnabled:  true,
		logLevel:      "info",
		bypassDomains: make([]string, 0),
		allowedIPs:    make([]string, 0),
		maxConnsLimit: 1000,
		pipelineLogs:  make([]string, 0),
	}
}

// ScrapeAndEncode simulates scraping proxy strings from sources and encoding them.
func (f *ForcerunPipeline) ScrapeAndEncode() (string, error) {
	var combinedData strings.Builder

	for _, source := range f.sources {
		log.Printf("F0rc3Run-panel: Scraping nodes from %s", source)

		// Simulated scrape
		// resp, err := http.Get(source)
		// ...

		// Simulated parsed nodes
		nodes := []string{
			fmt.Sprintf("vmess://%s", base64.StdEncoding.EncodeToString([]byte(`{"add":"127.0.0.1","port":443}`))),
			"vless://uuid@127.0.0.1:443?encryption=none&security=tls&type=ws",
		}

		for _, node := range nodes {
			combinedData.WriteString(node + "\n")
		}
	}

	// Base64 encode the combined subscription text
	encodedSub := base64.StdEncoding.EncodeToString([]byte(combinedData.String()))
	return encodedSub, nil
}

// PublishHandler is an HTTP handler to dynamically serve the encoded subscription.
func (f *ForcerunPipeline) PublishHandler(w http.ResponseWriter, r *http.Request) {
	data, err := f.ScrapeAndEncode()
	if err != nil {
		http.Error(w, "Failed to generate subscription", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
	log.Printf("F0rc3Run-panel: Published multi-protocol subscription to %s", r.RemoteAddr)
}

// SetSources overrides pipeline input source URLs.
func (f *ForcerunPipeline) SetSources(sources []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]string, len(sources))
	copy(copied, sources)
	f.sources = copied
}

// GetSources retrieves pipeline input source URLs.
func (f *ForcerunPipeline) GetSources() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	copied := make([]string, len(f.sources))
	copy(copied, f.sources)
	return copied
}

// SetVersion overrides configuration schema version.
func (f *ForcerunPipeline) SetVersion(v int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version = v
}

// GetVersion retrieves configuration schema version.
func (f *ForcerunPipeline) GetVersion() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.version
}

// SetCacheEnabled overrides dynamic caching variables.
func (f *ForcerunPipeline) SetCacheEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cacheEnabled = enabled
}

// GetCacheEnabled retrieves dynamic caching variables.
func (f *ForcerunPipeline) GetCacheEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.cacheEnabled
}

// SetLogLevel overrides diagnostic log levels.
func (f *ForcerunPipeline) SetLogLevel(level string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logLevel = level
}

// GetLogLevel retrieves diagnostic log levels.
func (f *ForcerunPipeline) GetLogLevel() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.logLevel
}

// SetMaxConnsLimit overrides concurrent connection cap parameters.
func (f *ForcerunPipeline) SetMaxConnsLimit(limit int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.maxConnsLimit = limit
}

// GetMaxConnsLimit retrieves concurrent connection cap parameters.
func (f *ForcerunPipeline) GetMaxConnsLimit() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.maxConnsLimit
}

// SetTimeout overrides HTTP Client timeout bounds.
func (f *ForcerunPipeline) SetTimeout(t time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.httpClient.Timeout = t
}

// GetTimeout retrieves HTTP Client timeout bounds.
func (f *ForcerunPipeline) GetTimeout() time.Duration {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.httpClient.Timeout
}

// SetBypassDomains overrides target bypass domains array.
func (f *ForcerunPipeline) SetBypassDomains(domains []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]string, len(domains))
	copy(copied, domains)
	f.bypassDomains = copied
}

// GetBypassDomains retrieves target bypass domains array.
func (f *ForcerunPipeline) GetBypassDomains() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	copied := make([]string, len(f.bypassDomains))
	copy(copied, f.bypassDomains)
	return copied
}

// SetAllowedIPs overrides target allowed IP addresses array.
func (f *ForcerunPipeline) SetAllowedIPs(ips []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]string, len(ips))
	copy(copied, ips)
	f.allowedIPs = copied
}

// GetAllowedIPs retrieves target allowed IP addresses array.
func (f *ForcerunPipeline) GetAllowedIPs() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	copied := make([]string, len(f.allowedIPs))
	copy(copied, f.allowedIPs)
	return copied
}

// SetActiveConns overrides active connection counter.
func (f *ForcerunPipeline) SetActiveConns(val int32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activeConns = val
}

// GetActiveConns retrieves active connection counter.
func (f *ForcerunPipeline) GetActiveConns() int32 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.activeConns
}

// SetPipelineLogs overrides internal logs array.
func (f *ForcerunPipeline) SetPipelineLogs(logs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]string, len(logs))
	copy(copied, logs)
	f.pipelineLogs = copied
}

// GetPipelineLogs retrieves internal logs array.
func (f *ForcerunPipeline) GetPipelineLogs() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	copied := make([]string, len(f.pipelineLogs))
	copy(copied, f.pipelineLogs)
	return copied
}
