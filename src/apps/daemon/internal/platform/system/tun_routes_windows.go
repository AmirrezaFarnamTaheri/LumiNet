//go:build windows

package system

import (
	"context"
	"fmt"
	hostprocess "github.com/maybeknott/luminet/internal/platform/process"
	"net"
	"os/exec"
	"strings"
)

// TunRoutingSupported reports whether host-route mutation is implemented.
func TunRoutingSupported() bool { return true }

func planTunRouteLease(ctx context.Context, deviceName, socksAddr string) (*tunRouteLease, error) {
	host, _, err := net.SplitHostPort(socksAddr)
	if err != nil {
		return nil, err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("resolve TUN proxy %q: %w", host, err)
	}
	gw, err := GetDefaultGateway(ctx)
	if err != nil {
		return nil, fmt.Errorf("default gateway: %w", err)
	}
	lease := &tunRouteLease{DeviceName: deviceName, ProxyAddress: socksAddr, Gateway: gw, DefaultRoute: true}
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		present, err := exactWindowsRouteExists(ctx, v4.String(), gw)
		if err != nil {
			return nil, err
		}
		if !present {
			lease.CreatedProxyIPs = append(lease.CreatedProxyIPs, v4.String())
		}
	}
	return lease, nil
}

func exactWindowsRouteExists(ctx context.Context, ip, gateway string) (bool, error) {
	cmd := exec.CommandContext(ctx, "route", "print", ip)
	cmd.SysProcAttr = hostprocess.GetHideWindowSysProcAttr()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("route print %s: %w", ip, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == ip && f[2] == gateway {
			return true, nil
		}
	}
	return false, nil
}

func runTunCommand(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = hostprocess.GetHideWindowSysProcAttr()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func applyTunRouteLease(ctx context.Context, lease *tunRouteLease) error {
	if lease == nil {
		return fmt.Errorf("nil TUN route lease")
	}
	if err := runTunCommand(ctx, "netsh", "interface", "ipv4", "set", "address", "name="+lease.DeviceName, "source=static", "address=10.0.0.2", "mask=255.255.255.0", "gateway=none"); err != nil {
		return err
	}
	added := []string{}
	for _, ip := range lease.CreatedProxyIPs {
		if err := runTunCommand(ctx, "route", "add", ip, "mask", "255.255.255.255", lease.Gateway, "metric", "1"); err != nil {
			cleanupCtx, cancel := context.WithCancel(context.Background())
			for _, a := range added {
				_ = runTunCommand(cleanupCtx, "route", "delete", a)
			}
			cancel()
			return err
		}
		added = append(added, ip)
	}
	if lease.DefaultRoute {
		if err := runTunCommand(ctx, "route", "add", "0.0.0.0", "mask", "0.0.0.0", "10.0.0.1", "metric", "5"); err != nil {
			cleanupCtx, cancel := context.WithCancel(context.Background())
			for _, a := range added {
				_ = runTunCommand(cleanupCtx, "route", "delete", a)
			}
			cancel()
			return err
		}
	}
	return nil
}

func removeTunRouteLease(ctx context.Context, lease *tunRouteLease) error {
	if lease == nil {
		return nil
	}
	var errs []error
	if lease.DefaultRoute {
		if err := runTunCommand(ctx, "route", "delete", "0.0.0.0", "mask", "0.0.0.0", "10.0.0.1"); err != nil {
			errs = append(errs, err)
		}
	}
	for _, ip := range lease.CreatedProxyIPs {
		if err := runTunCommand(ctx, "route", "delete", ip); err != nil {
			errs = append(errs, err)
		}
	}
	return errorsJoin(errs)
}

func errorsJoin(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("route cleanup: %v", errs)
}
