package mobilehost

import (
	"errors"
)

type MobileEngineState int

const (
	EngineStopped MobileEngineState = iota
	EngineStarting
	EngineRunning
	EngineDegraded
	EngineStopping
	EngineError
)

type MobileEngineMetrics struct {
	UptimeSecs    uint64 `json:"uptime_secs"`
	RxBytes       uint64 `json:"rx_bytes"`
	TxBytes       uint64 `json:"tx_bytes"`
	ActiveTunnels uint32 `json:"active_tunnels"`
	LastHeartbeat int64  `json:"last_heartbeat"`
}

type MobileEngineConfig struct {
	BindAddress string `json:"bind_address"`
	Socks5Port  uint16 `json:"socks5_port"`
	HttpPort    uint16 `json:"http_port"`
	DnsPort     uint16 `json:"dns_port"`
	MTU         uint32 `json:"mtu"`
	EnableIPv6  bool   `json:"enable_ipv6"`
}

type MobileEngineProvider struct {
	config    MobileEngineConfig
	state     MobileEngineState
	metrics   MobileEngineMetrics
	startTime int64
}

func NewMobileEngineProvider(config MobileEngineConfig) *MobileEngineProvider {
	return &MobileEngineProvider{
		config: config,
		state:  EngineStopped,
	}
}

func (m *MobileEngineProvider) StartEngine(timestamp int64) error {
	if m.state == EngineRunning {
		return errors.New("engine already running")
	}
	if m.config.Socks5Port == 0 || m.config.HttpPort == 0 {
		m.state = EngineError
		return errors.New("invalid port configuration")
	}

	m.state = EngineStarting
	m.startTime = timestamp
	m.metrics.LastHeartbeat = timestamp
	m.metrics.ActiveTunnels = 1
	m.state = EngineRunning
	return nil
}

func (m *MobileEngineProvider) StopEngine() error {
	if m.state == EngineStopped {
		return nil
	}
	m.state = EngineStopping
	m.metrics.ActiveTunnels = 0
	m.state = EngineStopped
	return nil
}

func (m *MobileEngineProvider) RecordTraffic(rx, tx uint64, timestamp int64) {
	m.metrics.RxBytes += rx
	m.metrics.TxBytes += tx
	m.metrics.LastHeartbeat = timestamp
	if m.startTime > 0 && timestamp >= m.startTime {
		m.metrics.UptimeSecs = uint64(timestamp - m.startTime)
	}
}

func (m *MobileEngineProvider) MarkDegraded(degraded bool) {
	if m.state == EngineRunning && degraded {
		m.state = EngineDegraded
	} else if m.state == EngineDegraded && !degraded {
		m.state = EngineRunning
	}
}

func (m *MobileEngineProvider) GetState() MobileEngineState {
	return m.state
}

func (m *MobileEngineProvider) GetMetrics() MobileEngineMetrics {
	return m.metrics
}
