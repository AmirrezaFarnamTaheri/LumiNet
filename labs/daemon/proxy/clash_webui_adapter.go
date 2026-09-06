// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: metacubexd-main
// Target path: server/internal/proxy/clash_webui_adapter.go

package proxy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
)

// ClashConfig represents general settings queried by MetaCubeXD dashboard.
type ClashConfig struct {
	Port       int    `json:"port"`
	SocksPort  int    `json:"socks-port"`
	RedirPort  int    `json:"redir-port"`
	TproxyPort int    `json:"tproxy-port"`
	Mode       string `json:"mode"` // "rule", "global", "direct"
	LogLevel   string `json:"log-level"`
	IPv6       bool   `json:"ipv6"`
}

// ClashWebUIAdapter implements MetaCubeXD configurations managers endpoints.
type ClashWebUIAdapter struct {
	mu     sync.RWMutex
	config ClashConfig
}

// NewClashWebUIAdapter instantiates the ClashWebUIAdapter.
func NewClashWebUIAdapter() *ClashWebUIAdapter {
	return &ClashWebUIAdapter{
		config: ClashConfig{
			Port:       7890,
			SocksPort:  7891,
			RedirPort:  7892,
			TproxyPort: 7893,
			Mode:       "rule",
			LogLevel:   "info",
			IPv6:       false,
		},
	}
}

// 1. GetConfig writes the current config structure.
func (c *ClashWebUIAdapter) GetConfig(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(c.config)
}

// 2. UpdateConfig updates properties based on client updates.
func (c *ClashWebUIAdapter) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var patch map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&patch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if modeVal, exists := patch["mode"]; exists {
		if modeStr, ok := modeVal.(string); ok {
			c.config.Mode = modeStr
		}
	}

	if logVal, exists := patch["log-level"]; exists {
		if logStr, ok := logVal.(string); ok {
			c.config.LogLevel = logStr
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// 3. TestDelay simulates latency checks for named proxies.
func (c *ClashWebUIAdapter) TestDelay(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "default"
	}

	res := map[string]interface{}{
		"delay": 120,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// 4. SelectProxy handles PUT /proxies/{group} request, selecting the active node.
func (c *ClashWebUIAdapter) SelectProxy(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Name string `json:"name"`
	}

	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("ClashWebUIAdapter: Changed proxy group outbound node target to: %s", payload.Name)
	w.WriteHeader(http.StatusNoContent)
}

// 5. SetPort configures HTTP proxy port.
func (c *ClashWebUIAdapter) SetPort(port int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.Port = port
}

// 6. GetPort returns HTTP proxy port.
func (c *ClashWebUIAdapter) GetPort() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config.Port
}

// 7. SetSocksPort configures SOCKS5 proxy port.
func (c *ClashWebUIAdapter) SetSocksPort(port int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.SocksPort = port
}

// 8. GetSocksPort returns SOCKS5 proxy port.
func (c *ClashWebUIAdapter) GetSocksPort() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config.SocksPort
}

// 9. SetRedirPort configures REDIR proxy port.
func (c *ClashWebUIAdapter) SetRedirPort(port int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.RedirPort = port
}

// 10. SetTproxyPort configures TPROXY proxy port.
func (c *ClashWebUIAdapter) SetTproxyPort(port int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.TproxyPort = port
}

// 11. SetMode configures proxy mode.
func (c *ClashWebUIAdapter) SetMode(mode string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if mode != "rule" && mode != "global" && mode != "direct" {
		return fmt.Errorf("invalid mode")
	}
	c.config.Mode = mode
	return nil
}

// 12. SetLogLevel configures debugging logs bounds.
func (c *ClashWebUIAdapter) SetLogLevel(level string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.LogLevel = level
}

// 13. SetIPv6Enabled configures IPv6 mapping status.
func (c *ClashWebUIAdapter) SetIPv6Enabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config.IPv6 = enabled
}

// 14. ResetConfig restores default configuration settings.
func (c *ClashWebUIAdapter) ResetConfig() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = ClashConfig{
		Port:       7890,
		SocksPort:  7891,
		RedirPort:  7892,
		TproxyPort: 7893,
		Mode:       "rule",
		LogLevel:   "info",
		IPv6:       false,
	}
}

// 15. ExportConfigJSON saves configurations database as JSON.
func (c *ClashWebUIAdapter) ExportConfigJSON(filePath string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := json.MarshalIndent(c.config, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}
