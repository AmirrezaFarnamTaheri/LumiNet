//go:build windows

package system

import (
	"context"
	"fmt"
	hostprocess "github.com/maybeknott/luminet/internal/platform/process"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const ncsiRegPath = `SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet`

// NCSISupported reports whether this build can read and mutate Windows NCSI.
func NCSISupported() bool { return true }

// NCSIConfig represents Windows NCSI parameters.
type NCSIConfig struct {
	ActiveWebProbeHost     string `json:"active_web_probe_host"`
	ActiveWebProbePath     string `json:"active_web_probe_path"`
	ActiveWebProbeContents string `json:"active_web_probe_contents"`
	ActiveDnsProbeHost     string `json:"active_dns_probe_host"`
	ActiveDnsProbeContent  string `json:"active_dns_probe_content"`
	EnableActiveProbing    uint32 `json:"enable_active_probing"`
}

// GetNCSIConfig reads NCSI registry parameters.
func GetNCSIConfig() (*NCSIConfig, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ncsiRegPath, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	getString := func(name string) (string, error) {
		value, _, err := k.GetStringValue(name)
		if err != nil {
			return "", fmt.Errorf("read NCSI %s: %w", name, err)
		}
		return value, nil
	}
	values := make(map[string]string, 5)
	for _, name := range []string{
		"ActiveWebProbeHost",
		"ActiveWebProbePath",
		"ActiveWebProbeContents",
		"ActiveDnsProbeHost",
		"ActiveDnsProbeContent",
	} {
		value, err := getString(name)
		if err != nil {
			return nil, err
		}
		values[name] = value
	}
	probing, _, err := k.GetIntegerValue("EnableActiveProbing")
	if err != nil {
		return nil, fmt.Errorf("read NCSI EnableActiveProbing: %w", err)
	}

	return &NCSIConfig{
		ActiveWebProbeHost:     values["ActiveWebProbeHost"],
		ActiveWebProbePath:     values["ActiveWebProbePath"],
		ActiveWebProbeContents: values["ActiveWebProbeContents"],
		ActiveDnsProbeHost:     values["ActiveDnsProbeHost"],
		ActiveDnsProbeContent:  values["ActiveDnsProbeContent"],
		EnableActiveProbing:    uint32(probing),
	}, nil
}

// SetNCSIConfig writes NCSI parameters and restarts NlaSvc.
func SetNCSIConfig(ctx context.Context, config *NCSIConfig) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ncsiRegPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	setString := func(name, value string) error {
		if err := k.SetStringValue(name, value); err != nil {
			return fmt.Errorf("set NCSI %s: %w", name, err)
		}
		return nil
	}
	for name, value := range map[string]string{
		"ActiveWebProbeHost":     config.ActiveWebProbeHost,
		"ActiveWebProbePath":     config.ActiveWebProbePath,
		"ActiveWebProbeContents": config.ActiveWebProbeContents,
		"ActiveDnsProbeHost":     config.ActiveDnsProbeHost,
		"ActiveDnsProbeContent":  config.ActiveDnsProbeContent,
	} {
		if err := setString(name, value); err != nil {
			return err
		}
	}
	if err := k.SetDWordValue("EnableActiveProbing", config.EnableActiveProbing); err != nil {
		return fmt.Errorf("set NCSI EnableActiveProbing: %w", err)
	}

	// Restart NlaSvc to apply changes. Failure must be visible so the host-network
	// transaction can roll back the registry mutation instead of reporting success.
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", "Restart-Service NlaSvc -Force")
	cmd.SysProcAttr = hostprocess.GetHideWindowSysProcAttr()
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restart NlaSvc: %w: %s", err, strings.TrimSpace(string(output)))
	}

	return nil
}

// ResetNCSIConfig resets the NCSI configuration back to standard Microsoft defaults.
func ResetNCSIConfig(ctx context.Context) error {
	defaults := DefaultNCSIConfig()
	return SetNCSIConfig(ctx, &defaults)
}

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
