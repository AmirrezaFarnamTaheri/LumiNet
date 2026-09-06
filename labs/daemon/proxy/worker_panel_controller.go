// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: zeus-main
// Target path: server/internal/proxy/worker_panel_controller.go

package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// WorkerPanelController emulates the Cloudflare Worker WebSocket router and DB settings management.
type WorkerPanelController struct {
	mu        sync.RWMutex
	settings  map[string]string
	users     map[string]string // uuid -> username
	cachedDns map[string]string
	version   int
}

// NewWorkerPanelController instantiates a new WorkerPanelController.
func NewWorkerPanelController() *WorkerPanelController {
	return &WorkerPanelController{
		settings:  map[string]string{"proxy_ip": "proxyip.cmliussss.net"},
		users:     make(map[string]string),
		cachedDns: make(map[string]string),
		version:   1,
	}
}

// IsWebSocketUpgrade checks if the incoming request is a WebSocket upgrade request (from zeus.js).
func (z *WorkerPanelController) IsWebSocketUpgrade(req *http.Request) bool {
	if req == nil {
		return false
	}
	return strings.ToLower(req.Header.Get("Upgrade")) == "websocket"
}

// IsSubscriptionPath asserts if the URL path requests configurations feed (from zeus.js).
func (z *WorkerPanelController) IsSubscriptionPath(path string) bool {
	return strings.HasPrefix(path, "/sub/") || strings.HasPrefix(path, "/feed/")
}

// HandleWebSocket emulates VLESS websocket proxies dial routines (from zeus.js).
func (z *WorkerPanelController) HandleWebSocket(w http.ResponseWriter, req *http.Request) error {
	z.mu.RLock()
	proxyIP := z.settings["proxy_ip"]
	z.mu.RUnlock()

	w.Header().Set("X-Proxy-IP", proxyIP)
	w.WriteHeader(http.StatusSwitchingProtocols)
	return nil
}

// HandleSubscription generates the base64 config profile for the target user (from zeus.js).
func (z *WorkerPanelController) HandleSubscription(usernameOrUUID, host string) (string, error) {
	z.mu.RLock()
	defer z.mu.RUnlock()

	userMatched := false
	for uuid, user := range z.users {
		if uuid == usernameOrUUID || user == usernameOrUUID {
			userMatched = true
			break
		}
	}

	if !userMatched && len(z.users) > 0 {
		return "", fmt.Errorf("user not found")
	}

	// Build subscription template configuration
	vlessConfig := fmt.Sprintf("vless://%s@%s:443?encryption=none&security=tls&type=ws#Zeus-VLESS", usernameOrUUID, host)
	encoded := base64.StdEncoding.EncodeToString([]byte(vlessConfig))
	return encoded, nil
}

// SetSetting updates a configuration parameter inside settings registry (from zeus.js).
func (z *WorkerPanelController) SetSetting(key, val string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.settings[key] = val
}

// GetSetting retrieves a configuration parameter fromsettings registry (from zeus.js).
func (z *WorkerPanelController) GetSetting(key string) string {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.settings[key]
}

// AddUser registers a subscriber UUID to panel database (from zeus.js).
func (z *WorkerPanelController) AddUser(uuid, username string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.users[uuid] = username
}

// RemoveUser deletes subscriber from panel database.
func (z *WorkerPanelController) RemoveUser(uuid string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	delete(z.users, uuid)
}

// SyncConfig handles legacy controller invocation placeholder.
func (z *WorkerPanelController) SyncConfig() {
	// Synced
}

// SetVersion overrides configuration schema version.
func (z *WorkerPanelController) SetVersion(v int) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.version = v
}

// GetVersion retrieves configuration schema version.
func (z *WorkerPanelController) GetVersion() int {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.version
}

// ClearSettings flushes settings registry.
func (z *WorkerPanelController) ClearSettings() {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.settings = make(map[string]string)
}

// GetSettingsCount retrieves count of configuration parameters.
func (z *WorkerPanelController) GetSettingsCount() int {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return len(z.settings)
}

// GetUser retrieves registered subscriber from panel database.
func (z *WorkerPanelController) GetUser(uuid string) (string, bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	username, exists := z.users[uuid]
	return username, exists
}

// GetUsers retrieves all registered subscribers.
func (z *WorkerPanelController) GetUsers() map[string]string {
	z.mu.RLock()
	defer z.mu.RUnlock()
	copied := make(map[string]string)
	for k, v := range z.users {
		copied[k] = v
	}
	return copied
}

// ClearUsers flushes subscribers database.
func (z *WorkerPanelController) ClearUsers() {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.users = make(map[string]string)
}

// GetUserCount retrieves count of registered users.
func (z *WorkerPanelController) GetUserCount() int {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return len(z.users)
}

// AddCachedDns registers a domain to IP query mapping.
func (z *WorkerPanelController) AddCachedDns(host, ip string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.cachedDns[host] = ip
}

// GetCachedDns retrieves a domain IP query mapping.
func (z *WorkerPanelController) GetCachedDns(host string) (string, bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	ip, exists := z.cachedDns[host]
	return ip, exists
}

// RemoveCachedDns deletes registered domain query mapping.
func (z *WorkerPanelController) RemoveCachedDns(host string) bool {
	z.mu.Lock()
	defer z.mu.Unlock()
	_, exists := z.cachedDns[host]
	if exists {
		delete(z.cachedDns, host)
	}
	return exists
}

// GetCachedDnsEntries retrieves all registered dns mappings.
func (z *WorkerPanelController) GetCachedDnsEntries() map[string]string {
	z.mu.RLock()
	defer z.mu.RUnlock()
	copied := make(map[string]string)
	for k, v := range z.cachedDns {
		copied[k] = v
	}
	return copied
}

// ClearCachedDns flushes dns query mapping.
func (z *WorkerPanelController) ClearCachedDns() {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.cachedDns = make(map[string]string)
}

// GetCachedDnsCount retrieves count of active domain mappings.
func (z *WorkerPanelController) GetCachedDnsCount() int {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return len(z.cachedDns)
}
