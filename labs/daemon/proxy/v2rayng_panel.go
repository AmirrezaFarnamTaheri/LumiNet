// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: v2rayng-panel-main (V2Ray / X-UI / V2board deployment configurations)
// Target path: server/internal/proxy/v2rayng_panel.go

package proxy

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
)

// V2rayngPanel manages diagnostic panels metrics tracking and installation configurations (from README.md).
type V2rayngPanel struct {
	mu          sync.RWMutex
	clientStats map[string]int64
	version     string
	xuiPort     int
	xuiUser     string
	xuiPass     string
}

// NewV2rayngPanel initializes a new V2rayngPanel instance (from README.md).
func NewV2rayngPanel() *V2rayngPanel {
	return &V2rayngPanel{
		clientStats: make(map[string]int64),
		version:     "1.8.5",
		xuiPort:     54321,
		xuiUser:     "admin",
		xuiPass:     "admin",
	}
}

// GenerateUUID generates a random UUID (equivalent to uuidgen from README.md).
func (v *V2rayngPanel) GenerateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// GetDefaultVmessConfig returns the inbound configuration JSON for VMess (from README.md).
func (v *V2rayngPanel) GetDefaultVmessConfig(uuid string) string {
	if uuid == "" {
		uuid = v.GenerateUUID()
	}
	configTpl := `{
  "inbounds": [{
    "port": 443,
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "%s",
        "alterId": 64
      }]
    },
    "streamSettings": {
      "network": "ws",
      "wsSettings": {
        "path": "/v2ray"
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}`
	return fmt.Sprintf(configTpl, uuid)
}

// GetXuiAddress returns the default panel entrypoint URL (from README.md).
func (v *V2rayngPanel) GetXuiAddress(ip string) string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return fmt.Sprintf("http://%s:%d", ip, v.xuiPort)
}

// VerifyCredentials validates if provided values match X-UI defaults (from README.md).
func (v *V2rayngPanel) VerifyCredentials(user, pass string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.xuiUser == user && v.xuiPass == pass
}

// GetCertbotCommand builds SSL registration command script (from README.md).
func (v *V2rayngPanel) GetCertbotCommand(domain string) string {
	return fmt.Sprintf("sudo certbot --nginx -d %s --non-interactive --agree-tos --register-unsafely-without-email", domain)
}

// UpdateMetrics registers client requests traffic data.
func (v *V2rayngPanel) UpdateMetrics(client string, count int64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.clientStats[client] += count
}

// GetMetricsJSON exports client traffic telemetry metadata.
func (v *V2rayngPanel) GetMetricsJSON() (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	data, err := json.Marshal(v.clientStats)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
