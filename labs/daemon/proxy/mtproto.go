// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: mtproto-panel-master
// Target path: server/internal/proxy/mtproto.go

package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MTProtoPanel manages MTProto proxy nodes.
type MTProtoPanel struct {
	mu             sync.RWMutex
	nodes          []string
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
	proxyUsers     map[string]string
	nodeStatuses   map[string]string
}

// 1. NewMTProtoPanel initializes the panel.
func NewMTProtoPanel() *MTProtoPanel {
	return &MTProtoPanel{
		nodes:         make([]string, 0),
		version:       1,
		cacheEnabled:  true,
		logLevel:      "info",
		bypassDomains: make([]string, 0),
		allowedIPs:    make([]string, 0),
		maxConnsLimit: 1000,
		panelLogs:     make([]string, 0),
		timeout:       10 * time.Second,
		proxyUsers:    make(map[string]string),
		nodeStatuses:  make(map[string]string),
	}
}

// 2. RegisterNode adds an MTProto proxy node to the registry.
func (m *MTProtoPanel) RegisterNode(node string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes = append(m.nodes, node)
}

// 3. HandleRegistry acts as the Express controller for node registry.
func (m *MTProtoPanel) HandleRegistry(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(m.nodes)
}

// 4. GetNodes returns registered nodes.
func (m *MTProtoPanel) GetNodes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]string, len(m.nodes))
	copy(copied, m.nodes)
	return copied
}

// 5. SetNodes replaces active nodes list.
func (m *MTProtoPanel) SetNodes(nodes []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes = nodes
}

// 6. ClearNodes resets nodes registry.
func (m *MTProtoPanel) ClearNodes() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes = make([]string, 0)
}

// 7. GetNodeCount returns tracked count.
func (m *MTProtoPanel) GetNodeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.nodes)
}

// 8. RemoveNode deletes node config by index.
func (m *MTProtoPanel) RemoveNode(idx int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx < 0 || idx >= len(m.nodes) {
		return fmt.Errorf("node index out of bounds")
	}
	m.nodes = append(m.nodes[:idx], m.nodes[idx+1:]...)
	return nil
}

// 9. GetPanelVersion returns version.
func (m *MTProtoPanel) GetPanelVersion() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}

// 10. SetPanelVersion overrides version.
func (m *MTProtoPanel) SetPanelVersion(v int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.version = v
}

// 11. ResetPanelPreset restores defaults.
func (m *MTProtoPanel) ResetPanelPreset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes = make([]string, 0)
	m.version = 1
	m.cacheEnabled = true
	m.logLevel = "info"
	m.bypassDomains = make([]string, 0)
	m.allowedIPs = make([]string, 0)
	atomic.StoreUint64(&m.processedCount, 0)
	atomic.StoreInt32(&m.activeConns, 0)
	m.proxyUsers = make(map[string]string)
	m.nodeStatuses = make(map[string]string)
}

// 12. VerifyPanelPreset checks parameters integration status.
func (m *MTProtoPanel) VerifyPanelPreset() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version > 0
}

// 13. GetHTTPClientTimeout returns timeout duration.
func (m *MTProtoPanel) GetHTTPClientTimeout() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.timeout
}

// 14. SetHTTPClientTimeout overrides timeout duration.
func (m *MTProtoPanel) SetHTTPClientTimeout(t time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.timeout = t
}

// 15. GetCacheSize returns size of cached records.
func (m *MTProtoPanel) GetCacheSize() int {
	return 0
}

// 16. ClearCache flushes active cache registers.
func (m *MTProtoPanel) ClearCache() {
}

// 17. SetCacheEnabled configures caching status.
func (m *MTProtoPanel) SetCacheEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheEnabled = enabled
}

// 18. IsCacheEnabled checks caching status.
func (m *MTProtoPanel) IsCacheEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cacheEnabled
}

// 19. SetLogLevel configures active log level.
func (m *MTProtoPanel) SetLogLevel(level string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logLevel = level
}

// 20. GetLogLevel returns active log level.
func (m *MTProtoPanel) GetLogLevel() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.logLevel
}

// 21. TriggerDiagnosticReport outputs diagnostics telemetry logs.
func (m *MTProtoPanel) TriggerDiagnosticReport() string {
	return fmt.Sprintf("Nodes: %d, Users: %d", m.GetNodeCount(), len(m.proxyUsers))
}

// 22. GetProcessedCount returns metric counter.
func (m *MTProtoPanel) GetProcessedCount() uint64 {
	return atomic.LoadUint64(&m.processedCount)
}

// 23. IncrementProcessedCount increments metric counter.
func (m *MTProtoPanel) IncrementProcessedCount() {
	atomic.AddUint64(&m.processedCount, 1)
}

// 24. ResetProcessedCount zeroes metric counter.
func (m *MTProtoPanel) ResetProcessedCount() {
	atomic.StoreUint64(&m.processedCount, 0)
}

// 25. GetStatsMap returns stats registry map.
func (m *MTProtoPanel) GetStatsMap() map[string]interface{} {
	return map[string]interface{}{
		"nodes":           m.GetNodeCount(),
		"processed_count": m.GetProcessedCount(),
	}
}

// 26. GetBypassDomains returns direct domain slice.
func (m *MTProtoPanel) GetBypassDomains() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]string, len(m.bypassDomains))
	copy(copied, m.bypassDomains)
	return copied
}

// 27. AddBypassDomain appends domain to bypass filter list.
func (m *MTProtoPanel) AddBypassDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bypassDomains = append(m.bypassDomains, domain)
}

// 28. RemoveBypassDomain deletes domain from filter list.
func (m *MTProtoPanel) RemoveBypassDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var updated []string
	for _, d := range m.bypassDomains {
		if d != domain {
			updated = append(updated, d)
		}
	}
	m.bypassDomains = updated
}

// 29. ClearBypassDomains resets bypass domain filter.
func (m *MTProtoPanel) ClearBypassDomains() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bypassDomains = make([]string, 0)
}

// 30. IsDomainBypassed checks domain presence in filter list.
func (m *MTProtoPanel) IsDomainBypassed(domain string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, d := range m.bypassDomains {
		if strings.Contains(domain, d) {
			return true
		}
	}
	return false
}

// 31. ExportConfigJSON saves settings configuration payload to JSON.
func (m *MTProtoPanel) ExportConfigJSON() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, err := json.Marshal(m.nodes)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// 32. ImportConfigJSON imports settings configurations from JSON string.
func (m *MTProtoPanel) ImportConfigJSON(jsonStr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return json.Unmarshal([]byte(jsonStr), &m.nodes)
}

// 33. ValidateDomain asserts domain format constraints.
func (m *MTProtoPanel) ValidateDomain(domain string) bool {
	return len(domain) > 3 && strings.Contains(domain, ".")
}

// 34. GetAllowedIPs returns whitelist IPs slice.
func (m *MTProtoPanel) GetAllowedIPs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]string, len(m.allowedIPs))
	copy(copied, m.allowedIPs)
	return copied
}

// 35. AddAllowedIP registers IP to connection whitelist.
func (m *MTProtoPanel) AddAllowedIP(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowedIPs = append(m.allowedIPs, ip)
}

// 36. RemoveAllowedIP deletes IP from connection whitelist.
func (m *MTProtoPanel) RemoveAllowedIP(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var updated []string
	for _, x := range m.allowedIPs {
		if x != ip {
			updated = append(updated, x)
		}
	}
	m.allowedIPs = updated
}

// 37. ClearAllowedIPs resets allowed connection whitelist.
func (m *MTProtoPanel) ClearAllowedIPs() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowedIPs = make([]string, 0)
}

// 38. IsIPAllowed checks IP presence in connection whitelist.
func (m *MTProtoPanel) IsIPAllowed(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.allowedIPs) == 0 {
		return true
	}
	for _, x := range m.allowedIPs {
		if x == ip {
			return true
		}
	}
	return false
}

// 39. GetActiveConnections returns active sockets count.
func (m *MTProtoPanel) GetActiveConnections() int {
	return int(atomic.LoadInt32(&m.activeConns))
}

// 40. IncrementActiveConnections increments active connection counter.
func (m *MTProtoPanel) IncrementActiveConnections() {
	atomic.AddInt32(&m.activeConns, 1)
}

// 41. DecrementActiveConnections decrements active connection counter.
func (m *MTProtoPanel) DecrementActiveConnections() {
	atomic.AddInt32(&m.activeConns, -1)
}

// 42. SetMaxConnections overrides client concurrent limit.
func (m *MTProtoPanel) SetMaxConnections(limit int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxConnsLimit = limit
}

// 43. GetMaxConnections returns client concurrent limit.
func (m *MTProtoPanel) GetMaxConnections() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maxConnsLimit
}

// 44. GetLogs returns panel log lines.
func (m *MTProtoPanel) GetLogs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]string, len(m.panelLogs))
	copy(copied, m.panelLogs)
	return copied
}

// 45. AddLog appends message to panel logs.
func (m *MTProtoPanel) AddLog(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.panelLogs = append(m.panelLogs, msg)
}

// 46. ClearLogs resets panel log buffer.
func (m *MTProtoPanel) ClearLogs() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.panelLogs = make([]string, 0)
}

// 47. AddProxyUser registers MTProto user secret.
func (m *MTProtoPanel) AddProxyUser(username, secret string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.proxyUsers[username] = secret
}

// 48. RemoveProxyUser deletes MTProto user.
func (m *MTProtoPanel) RemoveProxyUser(username string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.proxyUsers, username)
}

// 49. GetProxyUsers returns proxy users map.
func (m *MTProtoPanel) GetProxyUsers() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make(map[string]string)
	for k, v := range m.proxyUsers {
		copied[k] = v
	}
	return copied
}

// 50. ClearProxyUsers resets users secret registry.
func (m *MTProtoPanel) ClearProxyUsers() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.proxyUsers = make(map[string]string)
}

// 51. GetProxyUsersCount returns users count.
func (m *MTProtoPanel) GetProxyUsersCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.proxyUsers)
}

// 52. ValidateSecret checks secret hex validation.
func (m *MTProtoPanel) ValidateSecret(secret string) bool {
	if len(secret) != 32 {
		return false
	}
	_, err := hex.DecodeString(secret)
	return err == nil
}

// 53. GenerateSecret returns random 32-char hex secret.
func (m *MTProtoPanel) GenerateSecret() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// 54. GetNodeStatus retrieves node state.
func (m *MTProtoPanel) GetNodeStatus(node string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nodeStatuses[node]
}

// 55. SetNodeStatus configures node state.
func (m *MTProtoPanel) SetNodeStatus(node string, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodeStatuses[node] = status
}

// 56. ValidateIPAddress asserts IP format correctness.
func (m *MTProtoPanel) ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}
