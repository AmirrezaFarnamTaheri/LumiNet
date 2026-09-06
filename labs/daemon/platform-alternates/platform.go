package platform

import (
	"context"
)

type Capability string

const (
	CapabilityDNSControl     Capability = "dns_control"
	CapabilityProxyControl   Capability = "proxy_control"
	CapabilityTunControl     Capability = "tun_control"
	CapabilityStartupControl Capability = "startup_control"
	CapabilityPacketCapture  Capability = "packet_capture"
	CapabilityNativeTray     Capability = "native_tray"
)

type ProxyState struct {
	Enabled bool
	Server  string
	PacURL  string
	Bypass  string
}

type Status struct {
	OS           string       `json:"os"`
	Arch         string       `json:"arch"`
	Capabilities []Capability `json:"capabilities"`
	Warnings     []string     `json:"warnings,omitempty"`
}

type Adapter interface {
	Status(ctx context.Context) Status
	GetDNS(ctx context.Context, iface string) ([]string, error)
	SetDNS(ctx context.Context, iface string, servers []string) error
	ResetDNS(ctx context.Context, iface string) error
	GetProxy(ctx context.Context) (*ProxyState, error)
	SetProxy(ctx context.Context, state ProxyState) error
	DisableProxy(ctx context.Context) error
}

var defaultAdapter Adapter

func Register(a Adapter) {
	defaultAdapter = a
}

func GetAdapter() Adapter {
	return defaultAdapter
}

