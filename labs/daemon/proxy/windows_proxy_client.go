// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: V2RayN-PRO
// Target path: server/internal/proxy/v2rayn_pro.go

package proxy

import (
	"encoding/json"
	"io/ioutil"
	"log/slog"
	"sync"
)

// V2RayNPro manages optimized Windows configuration DB properties.
type V2RayNPro struct {
	mu               sync.RWMutex
	tcpFastOpen      bool
	tcpNoDelay       bool
	tcpKeepAliveIdle int
	muxConcurrency   int
	fragmentPackets  string
	fragmentLength   string
	fragmentInterval string
}

// NewV2RayNPro initializes V2RayNPro with standard defaults.
func NewV2RayNPro() *V2RayNPro {
	return &V2RayNPro{
		tcpFastOpen:      true,
		tcpNoDelay:       true,
		tcpKeepAliveIdle: 100,
		muxConcurrency:   8,
		fragmentPackets:  "tlshello",
		fragmentLength:   "10-20",
		fragmentInterval: "10-20",
	}
}

// 1. OptimizeGFWKnocker applies GFW-knocker Xray adjustments and default fragment settings.
func (v *V2RayNPro) OptimizeGFWKnocker() map[string]interface{} {
	slog.Info("V2RayN-PRO", "status", "Applying GFW-knocker Xray adjustments and default fragment settings (10-20ms)")

	v.mu.RLock()
	fastOpen := v.tcpFastOpen
	noDelay := v.tcpNoDelay
	keepAlive := v.tcpKeepAliveIdle
	mux := v.muxConcurrency
	packets := v.fragmentPackets
	length := v.fragmentLength
	interval := v.fragmentInterval
	v.mu.RUnlock()

	return map[string]interface{}{
		"outbounds": []map[string]interface{}{
			{
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": "example.com",
							"port":    443,
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network":  "tcp",
					"security": "tls",
					"sockopt": map[string]interface{}{
						"tcpFastOpen":      fastOpen,
						"tcpKeepAliveIdle": keepAlive,
						"tcpNoDelay":       noDelay,
					},
				},
				"mux": map[string]interface{}{
					"enabled":     true,
					"concurrency": mux,
				},
				"fragment": map[string]interface{}{
					"packets":  packets,
					"length":   length,
					"interval": interval,
				},
			},
		},
	}
}

// 2. SetTCPFastOpen configures system fast open links.
func (v *V2RayNPro) SetTCPFastOpen(enabled bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tcpFastOpen = enabled
}

// 3. IsTCPFastOpen checks if fast open is active.
func (v *V2RayNPro) IsTCPFastOpen() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.tcpFastOpen
}

// 4. SetTCPNoDelay configures immediate transmission.
func (v *V2RayNPro) SetTCPNoDelay(enabled bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tcpNoDelay = enabled
}

// 5. IsTCPNoDelay checks if no delay option is active.
func (v *V2RayNPro) IsTCPNoDelay() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.tcpNoDelay
}

// 6. SetTCPKeepAliveIdle configures TCP keep-alive idle timeouts.
func (v *V2RayNPro) SetTCPKeepAliveIdle(sec int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tcpKeepAliveIdle = sec
}

// 7. GetTCPKeepAliveIdle returns active TCP idle timeouts.
func (v *V2RayNPro) GetTCPKeepAliveIdle() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.tcpKeepAliveIdle
}

// 8. SetMuxConcurrency configures concurrency bounds.
func (v *V2RayNPro) SetMuxConcurrency(n int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.muxConcurrency = n
}

// 9. GetMuxConcurrency returns active concurrency bounds.
func (v *V2RayNPro) GetMuxConcurrency() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.muxConcurrency
}

// 10. SetFragmentPackets overrides target packets category values.
func (v *V2RayNPro) SetFragmentPackets(p string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fragmentPackets = p
}

// 11. GetFragmentPackets returns active target packets category values.
func (v *V2RayNPro) GetFragmentPackets() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.fragmentPackets
}

// 12. SetFragmentLength configures split lengths.
func (v *V2RayNPro) SetFragmentLength(l string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fragmentLength = l
}

// 13. SetFragmentInterval configures split intervals.
func (v *V2RayNPro) SetFragmentInterval(i string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fragmentInterval = i
}

// 14. ResetToDefaults restores standard default settings.
func (v *V2RayNPro) ResetToDefaults() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tcpFastOpen = true
	v.tcpNoDelay = true
	v.tcpKeepAliveIdle = 100
	v.muxConcurrency = 8
	v.fragmentPackets = "tlshello"
	v.fragmentLength = "10-20"
	v.fragmentInterval = "10-20"
}

// 15. ExportSettingsJSON saves configuration to JSON.
func (v *V2RayNPro) ExportSettingsJSON(filePath string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	dataDump := map[string]interface{}{
		"tcp_fast_open":       v.tcpFastOpen,
		"tcp_no_delay":        v.tcpNoDelay,
		"tcp_keep_alive_idle": v.tcpKeepAliveIdle,
		"mux_concurrency":     v.muxConcurrency,
		"fragment_packets":    v.fragmentPackets,
		"fragment_length":     v.fragmentLength,
		"fragment_interval":   v.fragmentInterval,
	}

	data, err := json.MarshalIndent(dataDump, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}
