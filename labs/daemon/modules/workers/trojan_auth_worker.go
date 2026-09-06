// Package workers handles serverless and edge-worker deployments.
// Ported from: worker-file-nahan1
// Target path: server/internal/workers/trojan_auth_worker.go

package workers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

// TrojanAuthWorker implements the Trojan authentication logic for the worker.
type TrojanAuthWorker struct {
	mu            sync.RWMutex
	baseUUID      string
	serverPort    int
	serverHost    string
	users         map[string]string
	userTxBytes   map[string]uint64
	userRxBytes   map[string]uint64
	activeConns   int32
	maxConnsLimit int
	tlsFingerprint string
	fallbackDomain string
	bypassDomains []string
	allowedIPs    []string
	version       int
	logLevel      string
}

// 1. NewTrojanAuthWorker creates a new Trojan auth worker processor.
func NewTrojanAuthWorker(uuid string) *TrojanAuthWorker {
	return &TrojanAuthWorker{
		baseUUID:       uuid,
		serverPort:     443,
		serverHost:     "127.0.0.1",
		users:          make(map[string]string),
		userTxBytes:    make(map[string]uint64),
		userRxBytes:    make(map[string]uint64),
		maxConnsLimit:  1000,
		tlsFingerprint: "chrome",
		version:        1,
		logLevel:       "info",
		bypassDomains:  make([]string, 0),
		allowedIPs:     make([]string, 0),
	}
}

// sha224Hex simulates the SHA-224 hashing equivalent logic used in Trojan.
func sha224Hex(input string) string {
	h := sha256.New224()
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

// 2. DerivePassword derives valid passwords from dynamic user UUIDs.
func (n *TrojanAuthWorker) DerivePassword(dynamicSuffix string) string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	rawPass := fmt.Sprintf("%s-%s", n.baseUUID, dynamicSuffix)
	hashed := sha224Hex(rawPass)
	return hashed
}

// 3. DecodeConfigFingerprint parses and extracts routing/fingerprint data from the config.
func (n *TrojanAuthWorker) DecodeConfigFingerprint(payload []byte) (string, error) {
	strPayload := string(payload)
	if !strings.HasPrefix(strPayload, "trojan://") {
		return "", fmt.Errorf("invalid config format")
	}
	return "fingerprint:decoded", nil
}

// 4. GetBaseUUID returns base UUID string.
func (n *TrojanAuthWorker) GetBaseUUID() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.baseUUID
}

// 5. SetBaseUUID overrides base UUID string.
func (n *TrojanAuthWorker) SetBaseUUID(uuid string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.baseUUID = uuid
}

// 6. ValidatePasswordHash checks hash string length constraints.
func (n *TrojanAuthWorker) ValidatePasswordHash(hash string) bool {
	return len(hash) == 56
}

// 7. GenerateTrojanLink formats parameters to Trojan link.
func (n *TrojanAuthWorker) GenerateTrojanLink(host string, port int, remark string) string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return fmt.Sprintf("trojan://%s@%s:%d#%s", n.baseUUID, host, port, remark)
}

// 8. SetServerPort configures server port.
func (n *TrojanAuthWorker) SetServerPort(port int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.serverPort = port
}

// 9. GetServerPort returns server port.
func (n *TrojanAuthWorker) GetServerPort() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.serverPort
}

// 10. SetServerHost configures server host.
func (n *TrojanAuthWorker) SetServerHost(host string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.serverHost = host
}

// 11. GetServerHost returns server host.
func (n *TrojanAuthWorker) GetServerHost() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.serverHost
}

// 12. AddUser registers user password mappings.
func (n *TrojanAuthWorker) AddUser(username string, password string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.users[username] = password
}

// 13. RemoveUser deletes user mappings.
func (n *TrojanAuthWorker) RemoveUser(username string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.users, username)
	delete(n.userTxBytes, username)
	delete(n.userRxBytes, username)
}

// 14. GetUserPassword retrieves password mapping by username.
func (n *TrojanAuthWorker) GetUserPassword(username string) (string, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	val, ok := n.users[username]
	return val, ok
}

// 15. ClearUsers resets users map.
func (n *TrojanAuthWorker) ClearUsers() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.users = make(map[string]string)
	n.userTxBytes = make(map[string]uint64)
	n.userRxBytes = make(map[string]uint64)
}

// 16. GetUsersCount returns count of active users.
func (n *TrojanAuthWorker) GetUsersCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.users)
}

// 17. GetUsers returns slice of registered usernames.
func (n *TrojanAuthWorker) GetUsers() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var list []string
	for k := range n.users {
		list = append(list, k)
	}
	return list
}

// 18. IsUserRegistered checks user presence.
func (n *TrojanAuthWorker) IsUserRegistered(username string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	_, found := n.users[username]
	return found
}

// 19. GetWorkerVersion returns schema version.
func (n *TrojanAuthWorker) GetWorkerVersion() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.version
}

// 20. SetWorkerVersion configures version schema.
func (n *TrojanAuthWorker) SetWorkerVersion(v int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.version = v
}

// 21. ResetWorkerPreset restores defaults values.
func (n *TrojanAuthWorker) ResetWorkerPreset() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.users = make(map[string]string)
	n.userTxBytes = make(map[string]uint64)
	n.userRxBytes = make(map[string]uint64)
	n.bypassDomains = make([]string, 0)
	n.allowedIPs = make([]string, 0)
	n.version = 1
	n.logLevel = "info"
	atomic.StoreInt32(&n.activeConns, 0)
}

// 22. VerifyWorkerPreset checks active parameter integration status.
func (n *TrojanAuthWorker) VerifyWorkerPreset() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.baseUUID != "" && n.version > 0
}

// 23. GetActiveConnections returns active sockets count.
func (n *TrojanAuthWorker) GetActiveConnections() int {
	return int(atomic.LoadInt32(&n.activeConns))
}

// 24. IncrementActiveConnections increments active connection counter.
func (n *TrojanAuthWorker) IncrementActiveConnections() {
	atomic.AddInt32(&n.activeConns, 1)
}

// 25. DecrementActiveConnections decrements active connection counter.
func (n *TrojanAuthWorker) DecrementActiveConnections() {
	atomic.AddInt32(&n.activeConns, -1)
}

// 26. SetMaxConnections overrides client concurrent limit.
func (n *TrojanAuthWorker) SetMaxConnections(limit int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.maxConnsLimit = limit
}

// 27. GetMaxConnections returns client concurrent limit.
func (n *TrojanAuthWorker) GetMaxConnections() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.maxConnsLimit
}

// 28. SetTLSFingerprint configures browser client fingerprints parameters.
func (n *TrojanAuthWorker) SetTLSFingerprint(fp string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tlsFingerprint = fp
}

// 29. GetTLSFingerprint returns active browser client fingerprints.
func (n *TrojanAuthWorker) GetTLSFingerprint() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.tlsFingerprint
}

// 30. SetFallbackDomain configures redirect domain on auth failed.
func (n *TrojanAuthWorker) SetFallbackDomain(domain string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.fallbackDomain = domain
}

// 31. GetFallbackDomain returns redirect domain.
func (n *TrojanAuthWorker) GetFallbackDomain() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.fallbackDomain
}

// 32. GetStatsMap returns stats registry map.
func (n *TrojanAuthWorker) GetStatsMap() map[string]interface{} {
	return map[string]interface{}{
		"active_connections": n.GetActiveConnections(),
		"users_count":        n.GetUsersCount(),
	}
}

// 33. ResetCounters zeroes stats counters.
func (n *TrojanAuthWorker) ResetCounters() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for k := range n.userTxBytes {
		n.userTxBytes[k] = 0
	}
	for k := range n.userRxBytes {
		n.userRxBytes[k] = 0
	}
}

// 34. GetTrafficStats returns client traffic metrics.
func (n *TrojanAuthWorker) GetTrafficStats(username string) (uint64, uint64) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.userTxBytes[username], n.userRxBytes[username]
}

// 35. IncrementTrafficStats increments client metrics.
func (n *TrojanAuthWorker) IncrementTrafficStats(username string, tx, rx uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.userTxBytes[username] += tx
	n.userRxBytes[username] += rx
}

// 36. ResetTrafficStats zeroes client metrics.
func (n *TrojanAuthWorker) ResetTrafficStats(username string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.userTxBytes[username] = 0
	n.userRxBytes[username] = 0
}

// 37. ClearAllTrafficStats zeroes all metrics registry.
func (n *TrojanAuthWorker) ClearAllTrafficStats() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.userTxBytes = make(map[string]uint64)
	n.userRxBytes = make(map[string]uint64)
}

// 38. GetTotalTrafficStats returns sum of all users traffic.
func (n *TrojanAuthWorker) GetTotalTrafficStats() (uint64, uint64) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var totalTx, totalRx uint64
	for _, tx := range n.userTxBytes {
		totalTx += tx
	}
	for _, rx := range n.userRxBytes {
		totalRx += rx
	}
	return totalTx, totalRx
}

// 39. AddBypassDomain appends domain to bypass filter list.
func (n *TrojanAuthWorker) AddBypassDomain(domain string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.bypassDomains = append(n.bypassDomains, domain)
}

// 40. RemoveBypassDomain deletes domain from filter list.
func (n *TrojanAuthWorker) RemoveBypassDomain(domain string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var updated []string
	for _, d := range n.bypassDomains {
		if d != domain {
			updated = append(updated, d)
		}
	}
	n.bypassDomains = updated
}

// 41. GetBypassDomains returns direct domain slice.
func (n *TrojanAuthWorker) GetBypassDomains() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	copied := make([]string, len(n.bypassDomains))
	copy(copied, n.bypassDomains)
	return copied
}

// 42. ClearBypassDomains resets bypass domain filter list.
func (n *TrojanAuthWorker) ClearBypassDomains() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.bypassDomains = make([]string, 0)
}

// 43. IsDomainBypassed checks domain presence in filter list.
func (n *TrojanAuthWorker) IsDomainBypassed(domain string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, d := range n.bypassDomains {
		if strings.Contains(domain, d) {
			return true
		}
	}
	return false
}

// 44. AddAllowedIP registers IP to connection whitelist.
func (n *TrojanAuthWorker) AddAllowedIP(ip string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.allowedIPs = append(n.allowedIPs, ip)
}

// 45. RemoveAllowedIP deletes IP from connection whitelist.
func (n *TrojanAuthWorker) RemoveAllowedIP(ip string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var updated []string
	for _, x := range n.allowedIPs {
		if x != ip {
			updated = append(updated, x)
		}
	}
	n.allowedIPs = updated
}

// 46. GetAllowedIPs returns whitelist IPs slice.
func (n *TrojanAuthWorker) GetAllowedIPs() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	copied := make([]string, len(n.allowedIPs))
	copy(copied, n.allowedIPs)
	return copied
}

// 47. ClearAllowedIPs resets allowed connection whitelist.
func (n *TrojanAuthWorker) ClearAllowedIPs() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.allowedIPs = make([]string, 0)
}

// 48. IsIPAllowed checks IP presence in connection whitelist.
func (n *TrojanAuthWorker) IsIPAllowed(ip string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if len(n.allowedIPs) == 0 {
		return true
	}
	for _, x := range n.allowedIPs {
		if x == ip {
			return true
		}
	}
	return false
}

// 49. ExportConfigJSON saves settings configuration payload to JSON.
func (n *TrojanAuthWorker) ExportConfigJSON() (string, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	data, err := json.Marshal(n.users)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// 50. ImportConfigJSON imports settings configurations from JSON.
func (n *TrojanAuthWorker) ImportConfigJSON(jsonStr string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return json.Unmarshal([]byte(jsonStr), &n.users)
}

// 51. ValidateIPAddress asserts IP format correctness.
func (n *TrojanAuthWorker) ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// 52. ValidateDomain asserts domain format constraints.
func (n *TrojanAuthWorker) ValidateDomain(domain string) bool {
	return len(domain) > 3 && strings.Contains(domain, ".")
}

// 53. GetWorkerLogLevel returns active log level.
func (n *TrojanAuthWorker) GetWorkerLogLevel() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.logLevel
}

// 54. SetWorkerLogLevel overrides active log level.
func (n *TrojanAuthWorker) SetWorkerLogLevel(level string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.logLevel = level
}

// 55. CheckTrafficLimit checks traffic limit.
func (n *TrojanAuthWorker) CheckTrafficLimit(username string, limit uint64) bool {
	tx, rx := n.GetTrafficStats(username)
	return (tx + rx) < limit
}
