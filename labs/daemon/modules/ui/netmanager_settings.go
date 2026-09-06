// Package ui implements admin panel models, wireguard obfuscation, and subscription services.
// Ported from: NetManager-main (lib/models/, lib/settings/)
// Target path: server/internal/ui/netmanager_settings.go

package ui

import "fmt"

// NetManagerServerInfo models runtime connection states.
type NetManagerServerInfo struct {
	ServerID        string `json:"server_id"`
	ServerName      string `json:"server_name"`
	Protocol        string `json:"protocol"`
	RemoteIP        string `json:"remote_ip"`
	Status          string `json:"status"` // connected, disconnected, connecting
	HandshakeTimeMs int64  `json:"handshake_time_ms"`
	RxBytes         int64  `json:"rx_bytes"`
	TxBytes         int64  `json:"tx_bytes"`
}

// Getters & Setters for NetManagerServerInfo
func (info *NetManagerServerInfo) GetServerID() string { return info.ServerID }
func (info *NetManagerServerInfo) SetServerID(v string) { info.ServerID = v }
func (info *NetManagerServerInfo) GetStatus() string { return info.Status }
func (info *NetManagerServerInfo) SetStatus(v string) { info.Status = v }
func (info *NetManagerServerInfo) GetRxBytes() int64 { return info.RxBytes }
func (info *NetManagerServerInfo) SetRxBytes(v int64) { info.RxBytes = v }

// NetManagerSettings defines the client application parameters.
type NetManagerSettings struct {
	DeviceName             string                 `json:"device_name"`
	ServerList             []NetManagerServerInfo `json:"server_list"`
	SelectedServerID       string                 `json:"selected_server_id"`
	LogPath                string                 `json:"log_path"`
	NotificationEnabled    bool                   `json:"notification_enabled"`
	KeepAliveIntervalSecs  int                    `json:"keep_alive_interval_secs"`
	AutostartOnBoot        bool                   `json:"autostart_on_boot"`
}

// Getters & Setters for NetManagerSettings
func (s *NetManagerSettings) GetDeviceName() string { return s.DeviceName }
func (s *NetManagerSettings) SetDeviceName(v string) { s.DeviceName = v }
func (s *NetManagerSettings) GetSelectedServerID() string { return s.SelectedServerID }
func (s *NetManagerSettings) SetSelectedServerID(v string) { s.SelectedServerID = v }

// FormatSettingsIdentifier returns settings token.
func (s *NetManagerSettings) FormatSettingsIdentifier() string {
	return fmt.Sprintf("device-%s-selected-%s", s.DeviceName, s.SelectedServerID)
}

// Additional getters & setters for NetManagerServerInfo
func (info *NetManagerServerInfo) GetServerName() string { return info.ServerName }
func (info *NetManagerServerInfo) SetServerName(v string) { info.ServerName = v }
func (info *NetManagerServerInfo) GetProtocol() string { return info.Protocol }
func (info *NetManagerServerInfo) SetProtocol(v string) { info.Protocol = v }
func (info *NetManagerServerInfo) GetRemoteIP() string { return info.RemoteIP }
func (info *NetManagerServerInfo) SetRemoteIP(v string) { info.RemoteIP = v }
func (info *NetManagerServerInfo) GetHandshakeTimeMs() int64 { return info.HandshakeTimeMs }
func (info *NetManagerServerInfo) SetHandshakeTimeMs(v int64) { info.HandshakeTimeMs = v }
func (info *NetManagerServerInfo) GetTxBytes() int64 { return info.TxBytes }
func (info *NetManagerServerInfo) SetTxBytes(v int64) { info.TxBytes = v }

// Additional getters & setters for NetManagerSettings
func (s *NetManagerSettings) GetLogPath() string { return s.LogPath }
func (s *NetManagerSettings) SetLogPath(v string) { s.LogPath = v }
func (s *NetManagerSettings) GetNotificationEnabled() bool { return s.NotificationEnabled }
func (s *NetManagerSettings) SetNotificationEnabled(v bool) { s.NotificationEnabled = v }
func (s *NetManagerSettings) GetKeepAliveIntervalSecs() int { return s.KeepAliveIntervalSecs }
func (s *NetManagerSettings) SetKeepAliveIntervalSecs(v int) { s.KeepAliveIntervalSecs = v }
func (s *NetManagerSettings) GetAutostartOnBoot() bool { return s.AutostartOnBoot }
func (s *NetManagerSettings) SetAutostartOnBoot(v bool) { s.AutostartOnBoot = v }
func (s *NetManagerSettings) GetServerList() []NetManagerServerInfo { return s.ServerList }
func (s *NetManagerSettings) SetServerList(v []NetManagerServerInfo) { s.ServerList = v }

// NetManagerBandwidthQuota defines monthly metric bounds.
type NetManagerBandwidthQuota struct {
	QuotaID      string
	MaxBytes     int64
	UsedBytes    int64
	BillingCycle string
}

// Getters & Setters for NetManagerBandwidthQuota
func (q *NetManagerBandwidthQuota) GetQuotaID() string { return q.QuotaID }
func (q *NetManagerBandwidthQuota) SetQuotaID(v string) { q.QuotaID = v }
func (q *NetManagerBandwidthQuota) GetMaxBytes() int64 { return q.MaxBytes }
func (q *NetManagerBandwidthQuota) SetMaxBytes(v int64) { q.MaxBytes = v }
func (q *NetManagerBandwidthQuota) GetUsedBytes() int64 { return q.UsedBytes }
func (q *NetManagerBandwidthQuota) SetUsedBytes(v int64) { q.UsedBytes = v }
func (q *NetManagerBandwidthQuota) GetBillingCycle() string { return q.BillingCycle }
func (q *NetManagerBandwidthQuota) SetBillingCycle(v string) { q.BillingCycle = v }

// NetManagerServerGroup categorizes server pools.
type NetManagerServerGroup struct {
	GroupID    int
	GroupName  string
	LatencyMax int
}

// Getters & Setters for NetManagerServerGroup
func (g *NetManagerServerGroup) GetGroupID() int { return g.GroupID }
func (g *NetManagerServerGroup) SetGroupID(v int) { g.GroupID = v }
func (g *NetManagerServerGroup) GetGroupName() string { return g.GroupName }
func (g *NetManagerServerGroup) SetGroupName(v string) { g.GroupName = v }
func (g *NetManagerServerGroup) GetLatencyMax() int { return g.LatencyMax }
func (g *NetManagerServerGroup) SetLatencyMax(v int) { g.LatencyMax = v }

// NetManagerSpeedtestMetrics represents speed test stages and metrics.
type NetManagerSpeedtestMetrics struct {
	Stage           string
	CurrentSpeed    float64
	Ping            int
	LatencyProgress float64
	Jitter          int
	PacketLoss      float64
	DownloadResult  float64
	UploadResult    float64
	MaxSpeedScale   float64
	Progress        float64
}

// Getters & Setters for NetManagerSpeedtestMetrics
func (m *NetManagerSpeedtestMetrics) GetStage() string { return m.Stage }
func (m *NetManagerSpeedtestMetrics) SetStage(v string) { m.Stage = v }
func (m *NetManagerSpeedtestMetrics) GetCurrentSpeed() float64 { return m.CurrentSpeed }
func (m *NetManagerSpeedtestMetrics) SetCurrentSpeed(v float64) { m.CurrentSpeed = v }
func (m *NetManagerSpeedtestMetrics) GetPing() int { return m.Ping }
func (m *NetManagerSpeedtestMetrics) SetPing(v int) { m.Ping = v }
func (m *NetManagerSpeedtestMetrics) GetLatencyProgress() float64 { return m.LatencyProgress }
func (m *NetManagerSpeedtestMetrics) SetLatencyProgress(v float64) { m.LatencyProgress = v }
func (m *NetManagerSpeedtestMetrics) GetJitter() int { return m.Jitter }
func (m *NetManagerSpeedtestMetrics) SetJitter(v int) { m.Jitter = v }
func (m *NetManagerSpeedtestMetrics) GetPacketLoss() float64 { return m.PacketLoss }
func (m *NetManagerSpeedtestMetrics) SetPacketLoss(v float64) { m.PacketLoss = v }
func (m *NetManagerSpeedtestMetrics) GetDownloadResult() float64 { return m.DownloadResult }
func (m *NetManagerSpeedtestMetrics) SetDownloadResult(v float64) { m.DownloadResult = v }
func (m *NetManagerSpeedtestMetrics) GetUploadResult() float64 { return m.UploadResult }
func (m *NetManagerSpeedtestMetrics) SetUploadResult(v float64) { m.UploadResult = v }
func (m *NetManagerSpeedtestMetrics) GetMaxSpeedScale() float64 { return m.MaxSpeedScale }
func (m *NetManagerSpeedtestMetrics) SetMaxSpeedScale(v float64) { m.MaxSpeedScale = v }
func (m *NetManagerSpeedtestMetrics) GetProgress() float64 { return m.Progress }
func (m *NetManagerSpeedtestMetrics) SetProgress(v float64) { m.Progress = v }

// NetManagerDeviceData maps active telephony hardware properties.
type NetManagerDeviceData struct {
	Manufacturer   string
	Modem          string
	Model          string
	AndroidVersion string
	BuildNumber    string
	SerialNumber   string
	IsVirtual      bool
}

// Getters & Setters for NetManagerDeviceData
func (d *NetManagerDeviceData) GetManufacturer() string { return d.Manufacturer }
func (d *NetManagerDeviceData) SetManufacturer(v string) { d.Manufacturer = v }
func (d *NetManagerDeviceData) GetModem() string { return d.Modem }
func (d *NetManagerDeviceData) SetModem(v string) { d.Modem = v }
func (d *NetManagerDeviceData) GetModel() string { return d.Model }
func (d *NetManagerDeviceData) SetModel(v string) { d.Model = v }
func (d *NetManagerDeviceData) GetAndroidVersion() string { return d.AndroidVersion }
func (d *NetManagerDeviceData) SetAndroidVersion(v string) { d.AndroidVersion = v }
func (d *NetManagerDeviceData) GetBuildNumber() string { return d.BuildNumber }
func (d *NetManagerDeviceData) SetBuildNumber(v string) { d.BuildNumber = v }
func (d *NetManagerDeviceData) GetSerialNumber() string { return d.SerialNumber }
func (d *NetManagerDeviceData) SetSerialNumber(v string) { d.SerialNumber = v }
func (d *NetManagerDeviceData) GetIsVirtual() bool { return d.IsVirtual }
func (d *NetManagerDeviceData) SetIsVirtual(v bool) { d.IsVirtual = v }
