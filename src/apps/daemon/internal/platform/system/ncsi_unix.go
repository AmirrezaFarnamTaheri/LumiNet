//go:build !windows

package system

import (
	"context"
	"fmt"
)

// NCSIConfig represents Windows NCSI parameters so the transport wire shape is
// stable across platforms even when the capability itself is unavailable.
type NCSIConfig struct {
	ActiveWebProbeHost     string `json:"active_web_probe_host"`
	ActiveWebProbePath     string `json:"active_web_probe_path"`
	ActiveWebProbeContents string `json:"active_web_probe_contents"`
	ActiveDnsProbeHost     string `json:"active_dns_probe_host"`
	ActiveDnsProbeContent  string `json:"active_dns_probe_content"`
	EnableActiveProbing    uint32 `json:"enable_active_probing"`
}

// NCSISupported reports whether this build can read or mutate Windows NCSI.
func NCSISupported() bool { return false }

func ncsiUnsupported() error {
	return fmt.Errorf("%w: Windows NCSI configuration", ErrUnsupportedPlatformFeature)
}

// GetNCSIConfig fails closed rather than returning synthetic Windows state.
func GetNCSIConfig() (*NCSIConfig, error) { return nil, ncsiUnsupported() }

// SetNCSIConfig fails closed rather than accepting a mutation it cannot apply.
func SetNCSIConfig(context.Context, *NCSIConfig) error { return ncsiUnsupported() }

// ResetNCSIConfig fails closed rather than reporting an unapplied reset.
func ResetNCSIConfig(context.Context) error { return ncsiUnsupported() }

func DefaultNCSIConfig() NCSIConfig {
	return NCSIConfig{
		ActiveWebProbeHost:     "www.msftconnecttest.com",
		ActiveWebProbePath:     "connecttest.txt",
		ActiveWebProbeContents: "Microsoft Connect Test",
		ActiveDnsProbeHost:     "dns.msftncsi.com",
		ActiveDnsProbeContent:  "131.107.255.255",
		EnableActiveProbing:    1,
	}
}
