package vpnstate

import (
	"sync"
)

// VPNState represents the active Android/Desktop VPN interface status.
type VPNState struct {
	IsConnected   bool   `json:"is_connected"`
	InterfaceName string `json:"interface_name"`
	LocalIPv4     string `json:"local_ipv4"`
	MTU           int    `json:"mtu"`
}

// VPNServiceBridge manages mobile and desktop VPN interface state inspired by RethinkDNS and DPITunnel Android.
type VPNServiceBridge struct {
	mu    sync.RWMutex
	state VPNState
}

// NewVPNServiceBridge creates a new VPN service state bridge.
func NewVPNServiceBridge() *VPNServiceBridge {
	return &VPNServiceBridge{
		state: VPNState{
			IsConnected:   false,
			InterfaceName: "tun0",
			LocalIPv4:     "10.0.0.2",
			MTU:           1500,
		},
	}
}

// UpdateState updates the active tunnel interface configuration.
func (b *VPNServiceBridge) UpdateState(connected bool, iface string, ip string, mtu int) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.state.IsConnected = connected
	if iface != "" {
		b.state.InterfaceName = iface
	}
	if ip != "" {
		b.state.LocalIPv4 = ip
	}
	if mtu > 0 {
		b.state.MTU = mtu
	}
}

// GetState returns the active VPN tunnel state.
func (b *VPNServiceBridge) GetState() VPNState {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.state
}
