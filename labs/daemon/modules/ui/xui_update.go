// Package ui implements admin panel models, wireguard obfuscation, and subscription services.
// Ported from: 3x-ui-main (main.go, update.sh)
// Target path: server/internal/ui/xui_update.go

package ui

import "fmt"

// XUIUpdateConfig defines automatic update configuration flags.
type XUIUpdateConfig struct {
	EnableAutoUpdate   bool   `json:"enable_auto_update"`
	UpdateIntervalDays int    `json:"update_interval_days"`
	ReleaseChannel     string `json:"release_channel"` // stable, beta, nightly
	SilentInstall      bool   `json:"silent_install"`
	AutoCleanLogs      bool   `json:"auto_clean_logs"`
}

// Getters & Setters for XUIUpdateConfig
func (c *XUIUpdateConfig) GetReleaseChannel() string { return c.ReleaseChannel }
func (c *XUIUpdateConfig) SetReleaseChannel(v string) { c.ReleaseChannel = v }

// XUISystemStatus holds runtime statistics parsed by the panel dashboard.
type XUISystemStatus struct {
	XrayRunning       bool    `json:"xray_running"`
	Version           string  `json:"version"`
	Uptime            int64   `json:"uptime"`
	CPUUsage          float64 `json:"cpu_usage"`
	MemoryUsage       float64 `json:"memory_usage"`
	DiskUsage         float64 `json:"disk_usage"`
	ActiveConnections int     `json:"active_connections"`
	TotalUsersCount   int     `json:"total_users_count"`
}

// Getters & Setters for XUISystemStatus
func (s *XUISystemStatus) GetVersion() string { return s.Version }
func (s *XUISystemStatus) SetVersion(v string) { s.Version = v }
func (s *XUISystemStatus) GetUptime() int64 { return s.Uptime }
func (s *XUISystemStatus) SetUptime(v int64) { s.Uptime = v }

// FormatStatusDebugString returns summary dashboard parameters.
func (s *XUISystemStatus) FormatStatusDebugString() string {
	return fmt.Sprintf("xui-status-%s-running-%t-uptime-%d", s.Version, s.XrayRunning, s.Uptime)
}
