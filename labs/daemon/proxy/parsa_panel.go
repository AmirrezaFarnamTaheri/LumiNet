// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Parsa-ultra-panel-main
// Target path: server/internal/proxy/parsa_panel.go

package proxy

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ParsaUser defines a request-based quota profile.
type ParsaUser struct {
	Username     string `json:"username"`
	RequestLimit int64  `json:"request_limit"`
	RequestCount int64  `json:"request_count"`
	Enabled      bool   `json:"enabled"`
}

// ParsaPanel coordinates Cloudflare D1 request-based billing, slave node clusters, and master keys.
type ParsaPanel struct {
	mu             sync.RWMutex
	MasterKey      string
	users          map[string]*ParsaUser
	slaveNodes     []string
	version        int
	processedCount uint64
	cacheEnabled   bool
	logLevel       string
	bypassDomains  []string
	allowedIPs     []string
	activeConns    int32
	maxConnsLimit  int
	panelLogs      []string
	timeout        time.Duration
	allowedDomains []string
	blockedIPs     []string
}

// NewParsaPanel instantiates a new ParsaPanel.
func NewParsaPanel(masterKey string) *ParsaPanel {
	return &ParsaPanel{
		MasterKey:      masterKey,
		users:          make(map[string]*ParsaUser),
		slaveNodes:     make([]string, 0),
		version:        1,
		cacheEnabled:   true,
		logLevel:       "info",
		bypassDomains:  make([]string, 0),
		allowedIPs:     make([]string, 0),
		maxConnsLimit:  1000,
		panelLogs:      make([]string, 0),
		timeout:        10 * time.Second,
		allowedDomains: make([]string, 0),
		blockedIPs:     make([]string, 0),
	}
}

// SubNodeBilling simulates D1 queries validation and quota charging.
func (p *ParsaPanel) SubNodeBilling(username string, requests int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	user, exists := p.users[username]
	if !exists || !user.Enabled {
		return false
	}
	if user.RequestCount+requests > user.RequestLimit {
		return false
	}
	user.RequestCount += requests
	atomic.AddUint64(&p.processedCount, uint64(requests))
	return true
}

// SetMasterKey overrides the panel master authorization key.
func (p *ParsaPanel) SetMasterKey(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.MasterKey = key
}

// GetMasterKey retrieves security key triggers.
func (p *ParsaPanel) GetMasterKey() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.MasterKey
}

// SetVersion overrides configuration version.
func (p *ParsaPanel) SetVersion(v int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.version = v
}

// GetVersion retrieves configuration version.
func (p *ParsaPanel) GetVersion() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.version
}

// SetCacheEnabled overrides dynamic caching variables status.
func (p *ParsaPanel) SetCacheEnabled(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cacheEnabled = enabled
}

// GetCacheEnabled retrieves dynamic caching variables status.
func (p *ParsaPanel) GetCacheEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cacheEnabled
}

// SetLogLevel overrides diagnostics log output severity level.
func (p *ParsaPanel) SetLogLevel(level string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logLevel = level
}

// GetLogLevel retrieves diagnostics log output severity level.
func (p *ParsaPanel) GetLogLevel() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.logLevel
}

// SetBypassDomains overrides target domains whitelist for direct routing.
func (p *ParsaPanel) SetBypassDomains(domains []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	copied := make([]string, len(domains))
	copy(copied, domains)
	p.bypassDomains = copied
}

// GetBypassDomains retrieves target domains whitelist for direct routing.
func (p *ParsaPanel) GetBypassDomains() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copied := make([]string, len(p.bypassDomains))
	copy(copied, p.bypassDomains)
	return copied
}

// AddBypassDomain registers bypass domain.
func (p *ParsaPanel) AddBypassDomain(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bypassDomains = append(p.bypassDomains, domain)
}

// RemoveBypassDomain deletes bypass domain.
func (p *ParsaPanel) RemoveBypassDomain(domain string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := -1
	for i, d := range p.bypassDomains {
		if d == domain {
			idx = i
			break
		}
	}
	if idx != -1 {
		p.bypassDomains = append(p.bypassDomains[:idx], p.bypassDomains[idx+1:]...)
		return true
	}
	return false
}

// ClearBypassDomains flushes bypass domains list.
func (p *ParsaPanel) ClearBypassDomains() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bypassDomains = make([]string, 0)
}

// GetBypassDomainsCount retrieves count of active bypass domains.
func (p *ParsaPanel) GetBypassDomainsCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.bypassDomains)
}

// SetAllowedIPs overrides target whitelisted client IPs.
func (p *ParsaPanel) SetAllowedIPs(ips []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	copied := make([]string, len(ips))
	copy(copied, ips)
	p.allowedIPs = copied
}

// GetAllowedIPs retrieves target whitelisted client IPs.
func (p *ParsaPanel) GetAllowedIPs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copied := make([]string, len(p.allowedIPs))
	copy(copied, p.allowedIPs)
	return copied
}

// AddAllowedIP registers allowed client IP.
func (p *ParsaPanel) AddAllowedIP(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedIPs = append(p.allowedIPs, ip)
}

// RemoveAllowedIP deletes whitelisted client IP.
func (p *ParsaPanel) RemoveAllowedIP(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := -1
	for i, v := range p.allowedIPs {
		if v == ip {
			idx = i
			break
		}
	}
	if idx != -1 {
		p.allowedIPs = append(p.allowedIPs[:idx], p.allowedIPs[idx+1:]...)
		return true
	}
	return false
}

// ClearAllowedIPs flushes whitelisted client IPs.
func (p *ParsaPanel) ClearAllowedIPs() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedIPs = make([]string, 0)
}

// GetAllowedIPsCount retrieves count of whitelisted client IPs.
func (p *ParsaPanel) GetAllowedIPsCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.allowedIPs)
}

// SetProcessedCount overrides total processed queries count.
func (p *ParsaPanel) SetProcessedCount(val uint64) {
	atomic.StoreUint64(&p.processedCount, val)
}

// GetProcessedCount retrieves total processed queries count.
func (p *ParsaPanel) GetProcessedCount() uint64 {
	return atomic.LoadUint64(&p.processedCount)
}

// SetActiveConnections overrides active connection count.
func (p *ParsaPanel) SetActiveConnections(val int32) {
	atomic.StoreInt32(&p.activeConns, val)
}

// GetActiveConnections retrieves active connection count.
func (p *ParsaPanel) GetActiveConnections() int32 {
	return atomic.LoadInt32(&p.activeConns)
}

// IncrementActiveConnections increments active connection counter.
func (p *ParsaPanel) IncrementActiveConnections() {
	atomic.AddInt32(&p.activeConns, 1)
}

// DecrementActiveConnections decrements active connection counter.
func (p *ParsaPanel) DecrementActiveConnections() {
	atomic.AddInt32(&p.activeConns, -1)
}

// SetMaxConnections overrides client concurrent limit.
func (p *ParsaPanel) SetMaxConnections(limit int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxConnsLimit = limit
}

// GetMaxConnections returns client concurrent limit.
func (p *ParsaPanel) GetMaxConnections() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.maxConnsLimit
}

// GetLogs returns panel log lines.
func (p *ParsaPanel) GetLogs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copied := make([]string, len(p.panelLogs))
	copy(copied, p.panelLogs)
	return copied
}

// AddLog appends message to panel logs.
func (p *ParsaPanel) AddLog(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.panelLogs = append(p.panelLogs, msg)
}

// ValidateIPAddress asserts IP format correctness.
func (p *ParsaPanel) ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// SetUsername overrides ParsaUser username key.
func (u *ParsaUser) SetUsername(name string) {
	u.Username = name
}

// GetUsername retrieves ParsaUser username key.
func (u *ParsaUser) GetUsername() string {
	return u.Username
}

// SetRequestLimit overrides ParsaUser quota threshold limit.
func (u *ParsaUser) SetRequestLimit(limit int64) {
	u.RequestLimit = limit
}

// GetRequestLimit retrieves ParsaUser quota threshold limit.
func (u *ParsaUser) GetRequestLimit() int64 {
	return u.RequestLimit
}

// SetRequestCount overrides ParsaUser consumed updates count.
func (u *ParsaUser) SetRequestCount(count int64) {
	u.RequestCount = count
}

// GetRequestCount retrieves ParsaUser consumed updates count.
func (u *ParsaUser) GetRequestCount() int64 {
	return u.RequestCount
}

// SetEnabled overrides ParsaUser activity toggle options.
func (u *ParsaUser) SetEnabled(enabled bool) {
	u.Enabled = enabled
}

// GetEnabled retrieves ParsaUser activity toggle options.
func (u *ParsaUser) GetEnabled() bool {
	return u.Enabled
}

// SetTimeout overrides ParsaPanel synchronization timeout bounds.
func (p *ParsaPanel) SetTimeout(t time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.timeout = t
}

// GetTimeout retrieves ParsaPanel synchronization timeout bounds.
func (p *ParsaPanel) GetTimeout() time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.timeout
}

// SetUsers overrides target panel user profiles mapping.
func (p *ParsaPanel) SetUsers(users map[string]*ParsaUser) {
	p.mu.Lock()
	defer p.mu.Unlock()
	copied := make(map[string]*ParsaUser)
	for k, v := range users {
		copied[k] = v
	}
	p.users = copied
}

// GetUsers retrieves target panel user profiles mapping.
func (p *ParsaPanel) GetUsers() map[string]*ParsaUser {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copied := make(map[string]*ParsaUser)
	for k, v := range p.users {
		copied[k] = v
	}
	return copied
}

// AddUser registers dynamic user quota profile.
func (p *ParsaPanel) AddUser(user *ParsaUser) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users[user.Username] = user
}

// RemoveUser deletes registered user quota profile.
func (p *ParsaPanel) RemoveUser(username string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, exists := p.users[username]
	if exists {
		delete(p.users, username)
	}
	return exists
}

// ClearUsers flushes panel users registry.
func (p *ParsaPanel) ClearUsers() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users = make(map[string]*ParsaUser)
}

// GetUsersCount retrieves count of active quota users.
func (p *ParsaPanel) GetUsersCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.users)
}

// SetSlaveNodes overrides target slave nodes cluster list.
func (p *ParsaPanel) SetSlaveNodes(nodes []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	copied := make([]string, len(nodes))
	copy(copied, nodes)
	p.slaveNodes = copied
}

// GetSlaveNodes retrieves target slave nodes cluster list.
func (p *ParsaPanel) GetSlaveNodes() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copied := make([]string, len(p.slaveNodes))
	copy(copied, p.slaveNodes)
	return copied
}

// AddSlaveNode registers a slave node in cluster.
func (p *ParsaPanel) AddSlaveNode(node string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.slaveNodes = append(p.slaveNodes, node)
}

// RemoveSlaveNode deletes registered slave node.
func (p *ParsaPanel) RemoveSlaveNode(node string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := -1
	for i, v := range p.slaveNodes {
		if v == node {
			idx = i
			break
		}
	}
	if idx != -1 {
		p.slaveNodes = append(p.slaveNodes[:idx], p.slaveNodes[idx+1:]...)
		return true
	}
	return false
}

// ClearSlaveNodes flushes slave nodes list.
func (p *ParsaPanel) ClearSlaveNodes() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.slaveNodes = make([]string, 0)
}

// GetSlaveNodesCount retrieves count of active slave nodes.
func (p *ParsaPanel) GetSlaveNodesCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.slaveNodes)
}

// SetAllowedDomains overrides whitelist of forwarded request domains.
func (p *ParsaPanel) SetAllowedDomains(domains []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	copied := make([]string, len(domains))
	copy(copied, domains)
	p.allowedDomains = copied
}

// GetAllowedDomains retrieves whitelist of forwarded request domains.
func (p *ParsaPanel) GetAllowedDomains() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copied := make([]string, len(p.allowedDomains))
	copy(copied, p.allowedDomains)
	return copied
}

// AddAllowedDomain registers domain to whitelist.
func (p *ParsaPanel) AddAllowedDomain(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedDomains = append(p.allowedDomains, domain)
}

// RemoveAllowedDomain deletes forwarding domain.
func (p *ParsaPanel) RemoveAllowedDomain(domain string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := -1
	for i, d := range p.allowedDomains {
		if d == domain {
			idx = i
			break
		}
	}
	if idx != -1 {
		p.allowedDomains = append(p.allowedDomains[:idx], p.allowedDomains[idx+1:]...)
		return true
	}
	return false
}

// ClearAllowedDomains flushes allowed domains whitelist.
func (p *ParsaPanel) ClearAllowedDomains() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedDomains = make([]string, 0)
}

// GetAllowedDomainsCount retrieves count of active whitelisted domains.
func (p *ParsaPanel) GetAllowedDomainsCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.allowedDomains)
}

// SetBlockedIPs overrides blacklist of target client IPs.
func (p *ParsaPanel) SetBlockedIPs(ips []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	copied := make([]string, len(ips))
	copy(copied, ips)
	p.blockedIPs = copied
}

// GetBlockedIPs retrieves blacklist of target client IPs.
func (p *ParsaPanel) GetBlockedIPs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copied := make([]string, len(p.blockedIPs))
	copy(copied, p.blockedIPs)
	return copied
}

// AddBlockedIP registers client IP to blacklist.
func (p *ParsaPanel) AddBlockedIP(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blockedIPs = append(p.blockedIPs, ip)
}

// RemoveBlockedIP deletes client IP from blacklist.
func (p *ParsaPanel) RemoveBlockedIP(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := -1
	for i, v := range p.blockedIPs {
		if v == ip {
			idx = i
			break
		}
	}
	if idx != -1 {
		p.blockedIPs = append(p.blockedIPs[:idx], p.blockedIPs[idx+1:]...)
		return true
	}
	return false
}

// ClearBlockedIPs flushes client IPs blacklist.
func (p *ParsaPanel) ClearBlockedIPs() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blockedIPs = make([]string, 0)
}

// GetBlockedIPsCount retrieves count of active blacklisted IPs.
func (p *ParsaPanel) GetBlockedIPsCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.blockedIPs)
}
