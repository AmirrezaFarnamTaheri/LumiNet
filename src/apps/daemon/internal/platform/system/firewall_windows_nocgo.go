//go:build windows && !cgo

package system

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
)

func runNetshNoCGO(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "netsh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// DNSLeakProtectionSupported reports whether WFP DNS leak protection is compiled in.
func DNSLeakProtectionSupported() bool { return false }

func EnableDnsLeakProtection(context.Context, string) error {
	return fmt.Errorf("%w: DNS leak protection requires CGO/WFP support", ErrUnsupportedPlatformFeature)
}

// DisableDnsLeakProtection remains available to the non-CGO watchdog so crash
// recovery can remove any named firewall rules even when WFP activation is not linked.
func DisableDnsLeakProtection(ctx context.Context) error {
	return runNetshNoCGO(ctx, "advfirewall", "firewall", "delete", "rule", "name=LumiNet DNS Leak Protection")
}
