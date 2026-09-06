// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: edgetunnel-main
// Target path: server/internal/proxy/edgetunnel.go

package proxy

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
)

// EdgeTunnel serves dynamic configurations based on User-Agent and handles fallback websites (from _worker.js).
type EdgeTunnel struct {
	mu             sync.RWMutex
	subPath        string
	proxyIP        string
	fakeWeb        string
	connsCount     int64
	version        int
	logLevel       string
	allowedDomains []string
	blockedIPs     []string
	uuid           string
	port           int
	tls            bool
	udp            bool
	network        string
}

// NewEdgeTunnel initializes a new EdgeTunnel manager.
func NewEdgeTunnel(subPath, proxyIP, fakeWeb string) *EdgeTunnel {
	return &EdgeTunnel{
		subPath:        subPath,
		proxyIP:        proxyIP,
		fakeWeb:        fakeWeb,
		version:        1,
		logLevel:       "info",
		allowedDomains: make([]string, 0),
		blockedIPs:     make([]string, 0),
		port:           443,
		tls:            true,
		udp:            true,
		network:        "ws",
	}
}

// ShouldIntercept returns true if request path matches subscription paths (from _worker.js).
func (e *EdgeTunnel) ShouldIntercept(path string) bool {
	e.mu.RLock()
	sub := e.subPath
	e.mu.RUnlock()

	return path == "/"+sub ||
		path == "/"+sub+"/v2ray" ||
		path == "/"+sub+"/clash" ||
		path == "/"+sub+"/info"
}

// GenerateConfig returns appropriate configuration content by User-Agent (from _worker.js).
func (e *EdgeTunnel) GenerateConfig(ua, host string) (string, string) {
	e.mu.RLock()
	proxyIP := e.proxyIP
	e.mu.RUnlock()

	ua = strings.ToLower(ua)
	if strings.Contains(ua, "clash") {
		// Return Clash YAML config format
		content := fmt.Sprintf(`
port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
proxies:
  - name: "Edge-VLESS"
    type: vless
    server: %s
    port: 443
    uuid: "some-uuid"
    udp: true
    tls: true
    network: ws
`, host)
		return content, "application/yaml"
	}

	// Return standard VLESS subscription share link base64 (from _worker.js)
	vless := fmt.Sprintf("vless://some-uuid@%s:443?encryption=none&security=tls&type=ws&host=%s#EdgeTunnel", proxyIP, host)
	encoded := base64.StdEncoding.EncodeToString([]byte(vless))
	return encoded, "text/plain; charset=utf-8"
}

// GetFakeWeb returns configured fallback website.
func (e *EdgeTunnel) GetFakeWeb() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.fakeWeb
}

// SetFakeWeb overrides fallback website.
func (e *EdgeTunnel) SetFakeWeb(w string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.fakeWeb = w
}

// SetSubPath overrides path parameter for client configurations.
func (e *EdgeTunnel) SetSubPath(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.subPath = path
}

// GetSubPath retrieves path parameter for client configurations.
func (e *EdgeTunnel) GetSubPath() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.subPath
}

// SetProxyIP overrides destination route connection address.
func (e *EdgeTunnel) SetProxyIP(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.proxyIP = ip
}

// GetProxyIP retrieves destination route connection address.
func (e *EdgeTunnel) GetProxyIP() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.proxyIP
}

// SetConnsCount overrides total logged requests count.
func (e *EdgeTunnel) SetConnsCount(val int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.connsCount = val
}

// GetConnsCount retrieves total logged requests count.
func (e *EdgeTunnel) GetConnsCount() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.connsCount
}

// SetVersion overrides configuration schema version.
func (e *EdgeTunnel) SetVersion(v int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.version = v
}

// GetVersion retrieves configuration schema version.
func (e *EdgeTunnel) GetVersion() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.version
}

// SetLogLevel overrides diagnostic log levels.
func (e *EdgeTunnel) SetLogLevel(level string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logLevel = level
}

// GetLogLevel retrieves diagnostic log levels.
func (e *EdgeTunnel) GetLogLevel() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.logLevel
}

// SetUUID overrides proxy target client key credentials.
func (e *EdgeTunnel) SetUUID(uuid string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.uuid = uuid
}

// GetUUID retrieves proxy target client key credentials.
func (e *EdgeTunnel) GetUUID() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.uuid
}

// SetPort overrides proxy target connection port.
func (e *EdgeTunnel) SetPort(port int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.port = port
}

// GetPort retrieves proxy target connection port.
func (e *EdgeTunnel) GetPort() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.port
}

// SetTLS overrides proxy target encryption status.
func (e *EdgeTunnel) SetTLS(tls bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tls = tls
}

// GetTLS retrieves proxy target encryption status.
func (e *EdgeTunnel) GetTLS() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.tls
}

// SetUDP overrides proxy target UDP capability status.
func (e *EdgeTunnel) SetUDP(udp bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.udp = udp
}

// GetUDP retrieves proxy target UDP capability status.
func (e *EdgeTunnel) GetUDP() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.udp
}

// SetNetwork overrides proxy target transport network framework.
func (e *EdgeTunnel) SetNetwork(net string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.network = net
}

// GetNetwork retrieves proxy target transport network framework.
func (e *EdgeTunnel) GetNetwork() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.network
}

// SetAllowedDomains overrides request forwarding domains list.
func (e *EdgeTunnel) SetAllowedDomains(domains []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	copied := make([]string, len(domains))
	copy(copied, domains)
	e.allowedDomains = copied
}

// GetAllowedDomains retrieves request forwarding domains list.
func (e *EdgeTunnel) GetAllowedDomains() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	copied := make([]string, len(e.allowedDomains))
	copy(copied, e.allowedDomains)
	return copied
}

// AddAllowedDomain registers domain to forwarding list.
func (e *EdgeTunnel) AddAllowedDomain(domain string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.allowedDomains = append(e.allowedDomains, domain)
}

// RemoveAllowedDomain deletes forwarding domain.
func (e *EdgeTunnel) RemoveAllowedDomain(domain string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	idx := -1
	for i, d := range e.allowedDomains {
		if d == domain {
			idx = i
			break
		}
	}
	if idx != -1 {
		e.allowedDomains = append(e.allowedDomains[:idx], e.allowedDomains[idx+1:]...)
		return true
	}
	return false
}

// ClearAllowedDomains flushes allowed domains forwarding list.
func (e *EdgeTunnel) ClearAllowedDomains() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.allowedDomains = make([]string, 0)
}

// GetAllowedDomainsCount retrieves count of active allowed domains.
func (e *EdgeTunnel) GetAllowedDomainsCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.allowedDomains)
}

// SetBlockedIPs overrides blacklist of target client IPs.
func (e *EdgeTunnel) SetBlockedIPs(ips []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	copied := make([]string, len(ips))
	copy(copied, ips)
	e.blockedIPs = copied
}

// GetBlockedIPs retrieves blacklist of target client IPs.
func (e *EdgeTunnel) GetBlockedIPs() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	copied := make([]string, len(e.blockedIPs))
	copy(copied, e.blockedIPs)
	return copied
}

// AddBlockedIP registers client IP to blacklist.
func (e *EdgeTunnel) AddBlockedIP(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockedIPs = append(e.blockedIPs, ip)
}

// RemoveBlockedIP deletes client IP from blacklist.
func (e *EdgeTunnel) RemoveBlockedIP(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	idx := -1
	for i, v := range e.blockedIPs {
		if v == ip {
			idx = i
			break
		}
	}
	if idx != -1 {
		e.blockedIPs = append(e.blockedIPs[:idx], e.blockedIPs[idx+1:]...)
		return true
	}
	return false
}

// ClearBlockedIPs flushes client IPs blacklist.
func (e *EdgeTunnel) ClearBlockedIPs() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockedIPs = make([]string, 0)
}

// GetBlockedIPsCount retrieves count of active blacklisted IPs.
func (e *EdgeTunnel) GetBlockedIPsCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.blockedIPs)
}
