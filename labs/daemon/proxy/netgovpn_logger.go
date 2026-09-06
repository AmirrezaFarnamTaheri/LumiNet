// Package proxy implements multi-protocol proxy servers and clients.
// Ported from: NetGoVPN-Android-main (v2ray/)
// Target path: server/internal/proxy/netgovpn_logger.go

package proxy

import "fmt"

// NetGoVPNLogEntry tracks diagnostics logs.
type NetGoVPNLogEntry struct {
	LogID     string `json:"log_id"`
	TimeStamp int64  `json:"time_stamp"`
	Level     string `json:"level"`
	Msg       string `json:"msg"`
	Component string `json:"component"`
}

// Getters & Setters for NetGoVPNLogEntry
func (l *NetGoVPNLogEntry) GetLogID() string  { return l.LogID }
func (l *NetGoVPNLogEntry) SetLogID(v string) { l.LogID = v }

// NetGoVPNDeviceState holds active device logs.
type NetGoVPNDeviceState struct {
	IsConnected              bool   `json:"is_connected"`
	IPAddress                string `json:"ip_address"`
	GatewayAddress           string `json:"gateway_address"`
	InterfaceName            string `json:"interface_name"`
	SignalStrengthPercentage int    `json:"signal_strength_percentage"`
	TrafficRx                int64  `json:"traffic_rx"`
	TrafficTx                int64  `json:"traffic_tx"`
}

// Getters & Setters for NetGoVPNDeviceState
func (d *NetGoVPNDeviceState) GetIPAddress() string              { return d.IPAddress }
func (d *NetGoVPNDeviceState) SetIPAddress(v string)             { d.IPAddress = v }
func (d *NetGoVPNDeviceState) GetIsConnected() bool              { return d.IsConnected }
func (d *NetGoVPNDeviceState) SetIsConnected(v bool)             { d.IsConnected = v }
func (d *NetGoVPNDeviceState) GetGatewayAddress() string         { return d.GatewayAddress }
func (d *NetGoVPNDeviceState) SetGatewayAddress(v string)        { d.GatewayAddress = v }
func (d *NetGoVPNDeviceState) GetInterfaceName() string          { return d.InterfaceName }
func (d *NetGoVPNDeviceState) SetInterfaceName(v string)         { d.InterfaceName = v }
func (d *NetGoVPNDeviceState) GetSignalStrengthPercentage() int  { return d.SignalStrengthPercentage }
func (d *NetGoVPNDeviceState) SetSignalStrengthPercentage(v int) { d.SignalStrengthPercentage = v }
func (d *NetGoVPNDeviceState) GetTrafficRx() int64               { return d.TrafficRx }
func (d *NetGoVPNDeviceState) SetTrafficRx(v int64)              { d.TrafficRx = v }
func (d *NetGoVPNDeviceState) GetTrafficTx() int64               { return d.TrafficTx }
func (d *NetGoVPNDeviceState) SetTrafficTx(v int64)              { d.TrafficTx = v }

// Additional getters & setters for NetGoVPNLogEntry
func (l *NetGoVPNLogEntry) GetTimeStamp() int64   { return l.TimeStamp }
func (l *NetGoVPNLogEntry) SetTimeStamp(v int64)  { l.TimeStamp = v }
func (l *NetGoVPNLogEntry) GetLevel() string      { return l.Level }
func (l *NetGoVPNLogEntry) SetLevel(v string)     { l.Level = v }
func (l *NetGoVPNLogEntry) GetMsg() string        { return l.Msg }
func (l *NetGoVPNLogEntry) SetMsg(v string)       { l.Msg = v }
func (l *NetGoVPNLogEntry) GetComponent() string  { return l.Component }
func (l *NetGoVPNLogEntry) SetComponent(v string) { l.Component = v }

// FormatDeviceStateString builds diagnostic tokens.
func (d *NetGoVPNDeviceState) FormatDeviceStateString() string {
	return fmt.Sprintf("vpn-connected-%t-ip-%s-rx-%d-tx-%d", d.IsConnected, d.IPAddress, d.TrafficRx, d.TrafficTx)
}
