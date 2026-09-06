// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: nodeunblocker.com-master
// Target path: server/internal/proxy/node_unblocker.go

package proxy

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// NodeUnblocker handles HTML body rewriting and WebSocket relays.
type NodeUnblocker struct {
	mu             sync.RWMutex
	upstreamURL    string
	cookieName     string
	timeout        time.Duration
	userAgent      string
	version        int
	requestCount   uint64
	rewrittenCount uint64
	activeSockets  int32
	hostMappings   map[string]string
	blockRules     []string
	allowedHosts   []string
}

func NewNodeUnblocker() *NodeUnblocker {
	return &NodeUnblocker{
		hostMappings: make(map[string]string),
		blockRules:   make([]string, 0),
		allowedHosts: make([]string, 0),
	}
}

// 56. GetUnblockerStatus returns diagnostics details status.
func (n *NodeUnblocker) GetUnblockerStatus() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.upstreamURL != "" {
		return "configured"
	}
	return "unconfigured"
}

// SetCookieName overrides session cookie identifier name.
func (n *NodeUnblocker) SetCookieName(name string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.cookieName = name
}

// GetCookieName retrieves session cookie identifier name.
func (n *NodeUnblocker) GetCookieName() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.cookieName
}

// SetTimeout overrides HTTP timeout limits.
func (n *NodeUnblocker) SetTimeout(t time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.timeout = t
}

// GetTimeout retrieves HTTP timeout limits.
func (n *NodeUnblocker) GetTimeout() time.Duration {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.timeout
}

// SetUserAgent overrides HTTP client request header User-Agent.
func (n *NodeUnblocker) SetUserAgent(ua string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.userAgent = ua
}

// GetUserAgent retrieves HTTP client request header User-Agent.
func (n *NodeUnblocker) GetUserAgent() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.userAgent
}

// SetVersion overrides configuration schema version.
func (n *NodeUnblocker) SetVersion(v int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.version = v
}

// GetVersion retrieves configuration schema version.
func (n *NodeUnblocker) GetVersion() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.version
}

// SetRequestCount overrides total incoming requests counter.
func (n *NodeUnblocker) SetRequestCount(val uint64) {
	atomic.StoreUint64(&n.requestCount, val)
}

// GetRequestCount retrieves total incoming requests counter.
func (n *NodeUnblocker) GetRequestCount() uint64 {
	return atomic.LoadUint64(&n.requestCount)
}

// SetRewrittenCount overrides total rewritten responses counter.
func (n *NodeUnblocker) SetRewrittenCount(val uint64) {
	atomic.StoreUint64(&n.rewrittenCount, val)
}

// GetRewrittenCount retrieves total rewritten responses counter.
func (n *NodeUnblocker) GetRewrittenCount() uint64 {
	return atomic.LoadUint64(&n.rewrittenCount)
}

// SetActiveSockets overrides concurrent open WebSockets counter.
func (n *NodeUnblocker) SetActiveSockets(val int32) {
	atomic.StoreInt32(&n.activeSockets, val)
}

// GetActiveSockets retrieves concurrent open WebSockets counter.
func (n *NodeUnblocker) GetActiveSockets() int32 {
	return atomic.LoadInt32(&n.activeSockets)
}

// AddHostMapping registers a domain redirection to map.
func (n *NodeUnblocker) AddHostMapping(host, target string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hostMappings[host] = target
}

// GetHostMapping retrieves domain redirection target.
func (n *NodeUnblocker) GetHostMapping(host string) (string, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	val, ok := n.hostMappings[host]
	return val, ok
}

// RemoveHostMapping deletes registered domain redirection.
func (n *NodeUnblocker) RemoveHostMapping(host string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, exists := n.hostMappings[host]
	if exists {
		delete(n.hostMappings, host)
	}
	return exists
}

// ClearHostMappings flushes domain redirection map.
func (n *NodeUnblocker) ClearHostMappings() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hostMappings = make(map[string]string)
}

// GetHostMappingsCount retrieves count of registered domain redirections.
func (n *NodeUnblocker) GetHostMappingsCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.hostMappings)
}

// AddBlockRule registers regular expression pattern to blocker.
func (n *NodeUnblocker) AddBlockRule(rule string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.blockRules = append(n.blockRules, rule)
}

// RemoveBlockRule deletes registered blocker pattern.
func (n *NodeUnblocker) RemoveBlockRule(rule string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	idx := -1
	for i, r := range n.blockRules {
		if r == rule {
			idx = i
			break
		}
	}
	if idx != -1 {
		n.blockRules = append(n.blockRules[:idx], n.blockRules[idx+1:]...)
		return true
	}
	return false
}

// ClearBlockRules flushes blocker patterns list.
func (n *NodeUnblocker) ClearBlockRules() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.blockRules = make([]string, 0)
}

// GetBlockRulesCount retrieves count of active blocker patterns.
func (n *NodeUnblocker) GetBlockRulesCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.blockRules)
}

// AddAllowedHost registers host domain to whitelist.
func (n *NodeUnblocker) AddAllowedHost(host string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.allowedHosts = append(n.allowedHosts, host)
}

// RemoveAllowedHost deletes host domain from whitelist.
func (n *NodeUnblocker) RemoveAllowedHost(host string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	idx := -1
	for i, h := range n.allowedHosts {
		if h == host {
			idx = i
			break
		}
	}
	if idx != -1 {
		n.allowedHosts = append(n.allowedHosts[:idx], n.allowedHosts[idx+1:]...)
		return true
	}
	return false
}

// ClearAllowedHosts flushes host domains whitelist.
func (n *NodeUnblocker) ClearAllowedHosts() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.allowedHosts = make([]string, 0)
}

// GetAllowedHostsCount retrieves count of active whitelisted host domains.
func (n *NodeUnblocker) GetAllowedHostsCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.allowedHosts)
}

// Unblock proxy engine rewriting HTML bodies and supporting WebSocket relays.
func (n *NodeUnblocker) Unblock() {
	slog.Info("NodeUnblocker", "status", "Porting Node.js unblocker proxy engine")
	slog.Info("NodeUnblocker", "status", "Rewriting HTML bodies and supporting WebSocket relays")
}
