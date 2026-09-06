//go:build darwin

package system

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func runNetworkSetup(ctx context.Context, args ...string) error {
	out, err := exec.CommandContext(ctx, "networksetup", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func networkSetupOutput(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "networksetup", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("networksetup %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func parseNetworkSetupProxy(out string) (enabled bool, server, port string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Enabled:"):
			enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "Enabled:")), "Yes")
		case strings.HasPrefix(line, "Server:"):
			server = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
		case strings.HasPrefix(line, "Port:"):
			port = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
		}
	}
	return
}

func parseAutoProxy(out string) (enabled bool, url string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Enabled:"):
			enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "Enabled:")), "Yes")
		case strings.HasPrefix(line, "URL:"):
			url = strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
		}
	}
	return
}

func SetSystemProxy(ctx context.Context, settings *ProxySettings) error {
	if settings == nil {
		return fmt.Errorf("proxy settings are required")
	}
	adapter, err := getDefaultAdapter(ctx)
	if err != nil {
		return err
	}
	if settings.PACURL != "" {
		if err := runNetworkSetup(ctx, "-setautoproxyurl", adapter, settings.PACURL); err != nil {
			return err
		}
		if err := runNetworkSetup(ctx, "-setautoproxystate", adapter, "on"); err != nil {
			return err
		}
		if err := runNetworkSetup(ctx, "-setwebproxystate", adapter, "off"); err != nil {
			return err
		}
		return runNetworkSetup(ctx, "-setsecurewebproxystate", adapter, "off")
	}
	if !settings.Enabled {
		if err := runNetworkSetup(ctx, "-setautoproxystate", adapter, "off"); err != nil {
			return err
		}
		if err := runNetworkSetup(ctx, "-setwebproxystate", adapter, "off"); err != nil {
			return err
		}
		return runNetworkSetup(ctx, "-setsecurewebproxystate", adapter, "off")
	}
	host, port, err := net.SplitHostPort(settings.Server)
	if err != nil {
		return fmt.Errorf("invalid proxy server %q: %w", settings.Server, err)
	}
	if err := runNetworkSetup(ctx, "-setautoproxystate", adapter, "off"); err != nil {
		return err
	}
	if err := runNetworkSetup(ctx, "-setwebproxy", adapter, host, port); err != nil {
		return err
	}
	if err := runNetworkSetup(ctx, "-setsecurewebproxy", adapter, host, port); err != nil {
		return err
	}
	if err := runNetworkSetup(ctx, "-setwebproxystate", adapter, "on"); err != nil {
		return err
	}
	return runNetworkSetup(ctx, "-setsecurewebproxystate", adapter, "on")
}

func GetSystemProxy(ctx context.Context) (*ProxySettings, error) {
	adapter, err := getDefaultAdapter(ctx)
	if err != nil {
		return nil, err
	}
	autoOut, err := networkSetupOutput(ctx, "-getautoproxyurl", adapter)
	if err != nil {
		return nil, err
	}
	if enabled, url := parseAutoProxy(autoOut); enabled {
		if url == "" {
			return nil, fmt.Errorf("automatic proxy enabled without URL")
		}
		return &ProxySettings{Enabled: true, PACURL: url}, nil
	}
	out, err := networkSetupOutput(ctx, "-getwebproxy", adapter)
	if err != nil {
		return nil, err
	}
	enabled, host, port := parseNetworkSetupProxy(out)
	if !enabled {
		return &ProxySettings{}, nil
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("manual proxy enabled without host/port")
	}
	return &ProxySettings{Enabled: true, Server: net.JoinHostPort(host, port)}, nil
}

func GetProxySettings(ctx context.Context) (*ProxySettings, error) { return GetSystemProxy(ctx) }
func SetProxySettings(ctx context.Context, settings ProxySettings) error {
	return SetSystemProxy(ctx, &settings)
}
func DisableSystemProxy(ctx context.Context) error { return SetSystemProxy(ctx, &ProxySettings{}) }
func DisableProxy(ctx context.Context) error       { return DisableSystemProxy(ctx) }
