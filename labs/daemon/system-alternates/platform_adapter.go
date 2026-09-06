package system

import (
	"context"
	"runtime"

	"github.com/maybeknott/luminet/internal/platform"
)

type SystemAdapter struct{}

func (a *SystemAdapter) Status(ctx context.Context) platform.Status {
	caps := []platform.Capability{
		platform.CapabilityDNSControl,
		platform.CapabilityProxyControl,
		platform.CapabilityStartupControl,
	}
	if runtime.GOOS == "windows" {
		caps = append(caps, platform.CapabilityTunControl)
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		caps = append(caps, platform.CapabilityPacketCapture)
	}

	var warnings []string
	if IsRunningInVM() {
		warnings = append(warnings, "Running inside a virtualized environment / sandbox")
	}
	if _, active := CheckLocalTorProxy(); active {
		warnings = append(warnings, "Local Tor proxy detected active on port 9050 or 9150")
	}

	return platform.Status{
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Capabilities: caps,
		Warnings:     warnings,
	}
}

func (a *SystemAdapter) GetDNS(ctx context.Context, iface string) ([]string, error) {
	return GetDNS(ctx, iface)
}

func (a *SystemAdapter) SetDNS(ctx context.Context, iface string, servers []string) error {
	return SetDNS(ctx, iface, servers)
}

func (a *SystemAdapter) ResetDNS(ctx context.Context, iface string) error {
	return ResetDNS(ctx, iface)
}

func (a *SystemAdapter) GetProxy(ctx context.Context) (*platform.ProxyState, error) {
	settings, err := GetSystemProxy(ctx)
	if err != nil {
		return nil, err
	}
	return &platform.ProxyState{
		Enabled: settings.Enabled,
		Server:  settings.Server,
		PacURL:  settings.PACURL,
		Bypass:  settings.Bypass,
	}, nil
}

func (a *SystemAdapter) SetProxy(ctx context.Context, state platform.ProxyState) error {
	return SetSystemProxy(ctx, &ProxySettings{
		Enabled: state.Enabled,
		Server:  state.Server,
		PACURL:  state.PacURL,
		Bypass:  state.Bypass,
	})
}

func (a *SystemAdapter) DisableProxy(ctx context.Context) error {
	return DisableSystemProxy(ctx)
}

// AndroidPrivateDNSDisable disables private DNS on Android for transparent proxying.
func (a *SystemAdapter) AndroidPrivateDNSDisable(ctx context.Context) error {
	return DisableAndroidPrivateDNS(ctx)
}

// AndroidPrivateDNSRestore restores private DNS on Android.
func (a *SystemAdapter) AndroidPrivateDNSRestore(ctx context.Context) error {
	return RestoreAndroidPrivateDNS(ctx)
}

// ConfigureFakeIPICMPDNAT configures DNAT for ICMP traffic to the fake IP range.
func (a *SystemAdapter) ConfigureFakeIPICMPDNAT(ctx context.Context, fakeIPRange string, tunIP string) error {
	return ConfigureFakeIPICMPDNAT(ctx, fakeIPRange, tunIP)
}

// RestoreIpsetBulk restores ipset rules in bulk.
func (a *SystemAdapter) RestoreIpsetBulk(ctx context.Context, rules string) error {
	return RestoreIpsetBulk(ctx, rules)
}

func init() {
	platform.Register(&SystemAdapter{})
}
