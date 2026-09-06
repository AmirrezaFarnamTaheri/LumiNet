// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: v2ray-core-master
// Target path: server/internal/proxy/v2ray_core_fork.go

package proxy

import (
	"encoding/json"
)

// V2RayForkMuxConfig manages connection multiplexing parameters for the custom fork.
type V2RayForkMuxConfig struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"` // default is 8
}

// V2RayForkConfig represents the custom fork parameters (including Flow control for XTLS).
type V2RayForkConfig struct {
	Log       V2RayLogConfig     `json:"log"`
	Inbounds  []V2RayInbound     `json:"inbounds"`
	Outbounds []V2RayOutbound    `json:"outbounds"`
	Mux       V2RayForkMuxConfig `json:"mux"`
}

// V2RayCoreFork handles V2Ray custom core fork integrations (e.g. XTLS flow and Mux controls).
type V2RayCoreFork struct {
	process managedConfigProcess
}

// NewV2RayCoreFork instantiates a V2RayCoreFork.
func NewV2RayCoreFork() *V2RayCoreFork {
	return &V2RayCoreFork{}
}

// GenerateConfigJSON compiles custom fork configurations.
func (v *V2RayCoreFork) GenerateConfigJSON(cfg V2RayForkConfig) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}

// Start launches the fork (xray/v2ray-fork) process.
func (v *V2RayCoreFork) Start(binaryPath string, cfg V2RayForkConfig) error {
	configBytes, err := v.GenerateConfigJSON(cfg)
	if err != nil {
		return err
	}
	return v.process.start(binaryPath, "v2ray_fork_config_*.json", configBytes, "fork process already running")
}

// Stop terminates the custom fork daemon.
func (v *V2RayCoreFork) Stop() error {
	return v.process.stop()
}

// Fork is the legacy interface trigger.
func (v *V2RayCoreFork) Fork() {
}
