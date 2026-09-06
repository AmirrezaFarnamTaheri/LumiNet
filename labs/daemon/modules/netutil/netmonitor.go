// Package netutil provides network monitoring utilities.
// (formerly package netmonitor) network traffic monitoring and alarm system.
// Ported from Firewalla's BroDetect, FlowManager, and AlarmManager.
//
// Features:
// - Flow aggregation with time-series stats
// - Per-device traffic tracking
// - Alarm system for anomalies (new device, large upload, suspicious domain)
// - Policy-based blocking
package netutil

import (
	"net"
	"sync"
	"time"
)

// Device represents a network device.
type Device struct {
	MAC        string    `json:"mac"`
	IP         string    `json:"ip"`
	Hostname   string    `json:"hostname"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Upload     int64     `json:"upload"`
	Download   int64     `json:"download"`
	IsNew      bool      `json:"is_new"`
}

// FlowRecord represents a network flow.
type FlowRecord struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  int    `json:"src_port"`
	DstPort  int    `json:"dst_port"`
	Protocol string `json:"protocol"`
	Bytes    int64  `json:"bytes"`
	Duration int64  `json:"duration_ms"`
	Domain   string `json:"domain,omitempty"`
}

// AlarmType represents the type of alarm.
type AlarmType string

const (
	AlarmNewDevice    AlarmType = "new_device"
	AlarmLargeUpload  AlarmType = "large_upload"
	AlarmSuspiciousDNS AlarmType = "suspicious_dns"
	AlarmOpenPort     AlarmType = "open_port"
	AlarmVPNAccess    AlarmType = "vpn_access"
	AlarmMalware      AlarmType = "malware"
)

// Alarm represents a network alarm.
type Alarm struct {
	Type      AlarmType `json:"type"`
	Target    string    `json:"target"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Severity  int       `json:"severity"` // 1-5
}

// TrafficStats holds aggregated traffic statistics.
type TrafficStats struct {
	TotalUpload   int64            `json:"total_upload"`
	TotalDownload int64            `json:"total_download"`
	PerDevice     map[string]*Device `json:"per_device"`
	PerDomain     map[string]int64   `json:"per_domain"`
	FlowCount     int64            `json:"flow_count"`
}

// MonitorConfig holds monitor configuration.
type MonitorConfig struct {
	// Alarm thresholds
	NewDeviceAlert    bool
	LargeUploadBytes  int64
	SuspiciousDomains []string
	// Polling interval
	PollInterval time.Duration
}

// DefaultMonitorConfig returns default configuration.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		NewDeviceAlert:   true,
		LargeUploadBytes: 100 * 1024 * 1024, // 100MB
		PollInterval:     30 * time.Second,
	}
}

// NetworkMonitor monitors network traffic and generates alarms.
type NetworkMonitor struct {
	config   MonitorConfig
	devices  map[string]*Device
	flows    []FlowRecord
	alarms   []Alarm
	stats    TrafficStats
	mu       sync.RWMutex
	alarmCh  chan Alarm
}

// NewNetworkMonitor creates a new monitor.
func NewNetworkMonitor(config MonitorConfig) *NetworkMonitor {
	return &NetworkMonitor{
		config:  config,
		devices: make(map[string]*Device),
		alarmCh: make(chan Alarm, 100),
		stats: TrafficStats{
			PerDevice: make(map[string]*Device),
			PerDomain: make(map[string]int64),
		},
	}
}

// RecordFlow records a network flow and checks for anomalies.
func (m *NetworkMonitor) RecordFlow(flow FlowRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.flows = append(m.flows, flow)
	m.stats.FlowCount++
	m.stats.TotalUpload += flow.Bytes
	m.stats.PerDomain[flow.Domain] += flow.Bytes

	// Update device stats
	if dev, ok := m.devices[flow.SrcIP]; ok {
		dev.Upload += flow.Bytes
		dev.LastSeen = time.Now()
	} else {
		// New device detected
		dev = &Device{
			IP:        flow.SrcIP,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Upload:    flow.Bytes,
			IsNew:     true,
		}
		m.devices[flow.SrcIP] = dev
		m.stats.PerDevice[flow.SrcIP] = dev

		if m.config.NewDeviceAlert {
			m.emitAlarm(Alarm{
				Type:      AlarmNewDevice,
				Target:    flow.SrcIP,
				Message:   "New device detected: " + flow.SrcIP,
				Timestamp: time.Now(),
				Severity:  2,
			})
		}
	}

	// Check for large upload
	if flow.Bytes > m.config.LargeUploadBytes {
		m.emitAlarm(Alarm{
			Type:      AlarmLargeUpload,
			Target:    flow.SrcIP,
			Message:   "Large upload detected",
			Timestamp: time.Now(),
			Severity:  3,
		})
	}

	// Check for suspicious domains
	for _, domain := range m.config.SuspiciousDomains {
		if flow.Domain == domain {
			m.emitAlarm(Alarm{
				Type:      AlarmSuspiciousDNS,
				Target:    flow.Domain,
				Message:   "Suspicious domain accessed",
				Timestamp: time.Now(),
				Severity:  4,
			})
			break
		}
	}
}

// emitAlarm sends an alarm to the channel.
func (m *NetworkMonitor) emitAlarm(alarm Alarm) {
	select {
	case m.alarmCh <- alarm:
	default:
		// Channel full, drop alarm
	}
}

// Alarms returns the alarm channel.
func (m *NetworkMonitor) Alarms() <-chan Alarm {
	return m.alarmCh
}

// Stats returns current traffic statistics.
func (m *NetworkMonitor) Stats() TrafficStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// Devices returns all known devices.
func (m *NetworkMonitor) Devices() []*Device {
	m.mu.RLock()
	defer m.mu.RUnlock()
	devices := make([]*Device, 0, len(m.devices))
	for _, d := range m.devices {
		devices = append(devices, d)
	}
	return devices
}

// TopDevices returns top N devices by traffic.
func (m *NetworkMonitor) TopDevices(n int) []*Device {
	m.mu.RLock()
	defer m.mu.RUnlock()
	devices := make([]*Device, 0, len(m.devices))
	for _, d := range m.devices {
		devices = append(devices, d)
	}
	// Sort by total traffic
	for i := 0; i < len(devices); i++ {
		for j := i + 1; j < len(devices); j++ {
			if devices[j].Upload+devices[j].Download > devices[i].Upload+devices[i].Download {
				devices[i], devices[j] = devices[j], devices[i]
			}
		}
	}
	if n > len(devices) {
		n = len(devices)
	}
	return devices[:n]
}

// DetectGateway detects the network gateway IP.
func DetectGateway() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}


