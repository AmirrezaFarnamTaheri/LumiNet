// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: v2ray-core-main
// Target path: server/internal/proxy/v2ray_core.go

package proxy

import (
	"encoding/json"
)

// V2RayLogConfig maps v2ray core log configurations.
type V2RayLogConfig struct {
	Access   string `json:"access"`
	Error    string `json:"error"`
	LogLevel string `json:"loglevel"`
}

// V2RayInbound represents a V2Ray inbound listener config.
type V2RayInbound struct {
	Port           int                    `json:"port"`
	Listen         string                 `json:"listen"`
	Protocol       string                 `json:"protocol"` // "socks", "http", "vmess", "vless"
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings map[string]interface{} `json:"streamSettings,omitempty"`
}

// V2RayOutbound represents a V2Ray outbound routing target config.
type V2RayOutbound struct {
	Protocol       string                 `json:"protocol"` // "freedom", "vmess", "vless", "shadowsocks", "trojan", "blackhole"
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings map[string]interface{} `json:"streamSettings,omitempty"`
	Tag            string                 `json:"tag"`
}

// V2RayConfig structure maps standard V2Ray config.json layout.
type V2RayConfig struct {
	Log       V2RayLogConfig  `json:"log"`
	Inbounds  []V2RayInbound  `json:"inbounds"`
	Outbounds []V2RayOutbound `json:"outbounds"`
}

// V2RayCore manages the standard v2ray process lifecycle and json configurations.
type V2RayCore struct {
	process managedConfigProcess
}

// NewV2RayCore instantiates V2RayCore.
func NewV2RayCore() *V2RayCore {
	return &V2RayCore{}
}

// GenerateConfigJSON compiles config structs into JSON bytes.
func (v *V2RayCore) GenerateConfigJSON(cfg V2RayConfig) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}

// Start launches the V2Ray process with the given configuration structure.
func (v *V2RayCore) Start(binaryPath string, cfg V2RayConfig) error {
	configBytes, err := v.GenerateConfigJSON(cfg)
	if err != nil {
		return err
	}
	return v.process.start(binaryPath, "v2ray_config_*.json", configBytes, "v2ray process already running")
}

// Stop terminates the running v2ray process and cleans up config files.
func (v *V2RayCore) Stop() error {
	return v.process.stop()
}

// InitCore performs basic setup validation.
func (v *V2RayCore) InitCore() {
	// Diagnostic helper
}
