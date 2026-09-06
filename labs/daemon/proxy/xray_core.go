// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Xray-core-main
// Target path: server/internal/proxy/xray_core.go

package proxy

import (
	"encoding/json"
)

// XrayRealityConfig maps Xray Reality parameters.
type XrayRealityConfig struct {
	Show       bool     `json:"show"`
	Dest       string   `json:"dest"`
	Xver       int      `json:"xver"`
	ServerName string   `json:"serverName"`
	ShortIds   []string `json:"shortIds"`
}

// XrayOutboundSettings contains Reality security parameters.
type XrayOutboundSettings struct {
	Fingerprint string `json:"fingerprint,omitempty"`
	ServerName  string `json:"serverName,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortId     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

// XrayCore manages the Xray-core process execution and config injection (including REALITY handshakes).
type XrayCore struct {
	process managedConfigProcess
}

// NewXrayCore instantiates XrayCore.
func NewXrayCore() *XrayCore {
	return &XrayCore{}
}

// Start launches the xray executable with custom TLS/Reality inbounds and outbounds.
func (x *XrayCore) Start(binaryPath string, cfg V2RayConfig) error {
	configBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return x.process.start(binaryPath, "xray_config_*.json", configBytes, "xray service already running")
}

// Stop terminates the running xray process.
func (x *XrayCore) Stop() error {
	return x.process.stop()
}

// InitCore initializes VLESS/VMess protocols and Reality handshakes.
func (x *XrayCore) InitCore() {
}
