//go:build linux

package system

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func runGSettings(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "gsettings", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gsettings %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func getGSettings(ctx context.Context, schema, key string) (string, error) {
	out, err := exec.CommandContext(ctx, "gsettings", "get", schema, key).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("gsettings get %s %s: %w: %s", schema, key, err, strings.TrimSpace(string(out)))
	}
	return strings.Trim(strings.TrimSpace(string(out)), "'\""), nil
}

// SetSystemProxy configures GNOME system proxy settings.
func SetSystemProxy(ctx context.Context, settings *ProxySettings) error {
	if settings == nil {
		return fmt.Errorf("proxy settings are required")
	}
	if settings.PACURL != "" {
		if err := runGSettings(ctx, "set", "org.gnome.system.proxy", "autoconfig-url", settings.PACURL); err != nil {
			return err
		}
		return runGSettings(ctx, "set", "org.gnome.system.proxy", "mode", "auto")
	}
	if !settings.Enabled {
		return runGSettings(ctx, "set", "org.gnome.system.proxy", "mode", "none")
	}

	host, portText, err := net.SplitHostPort(settings.Server)
	if err != nil {
		return fmt.Errorf("invalid proxy server %q: %w", settings.Server, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid proxy port %q", portText)
	}
	steps := [][]string{
		{"set", "org.gnome.system.proxy.http", "host", host},
		{"set", "org.gnome.system.proxy.http", "port", strconv.Itoa(port)},
		{"set", "org.gnome.system.proxy.https", "host", host},
		{"set", "org.gnome.system.proxy.https", "port", strconv.Itoa(port)},
		{"set", "org.gnome.system.proxy", "mode", "manual"},
	}
	for _, step := range steps {
		if err := runGSettings(ctx, step...); err != nil {
			return err
		}
	}
	return nil
}

// GetSystemProxy reads current GNOME system proxy settings.
func GetSystemProxy(ctx context.Context) (*ProxySettings, error) {
	mode, err := getGSettings(ctx, "org.gnome.system.proxy", "mode")
	if err != nil {
		return nil, err
	}
	s := &ProxySettings{}
	switch mode {
	case "none":
		return s, nil
	case "auto":
		s.Enabled = true
		s.PACURL, err = getGSettings(ctx, "org.gnome.system.proxy", "autoconfig-url")
		if err != nil {
			return nil, err
		}
		return s, nil
	case "manual":
		host, err := getGSettings(ctx, "org.gnome.system.proxy.http", "host")
		if err != nil {
			return nil, err
		}
		port, err := getGSettings(ctx, "org.gnome.system.proxy.http", "port")
		if err != nil {
			return nil, err
		}
		if host == "" || port == "" {
			return nil, fmt.Errorf("manual proxy mode has incomplete host/port")
		}
		s.Enabled = true
		s.Server = net.JoinHostPort(host, port)
		return s, nil
	default:
		return nil, fmt.Errorf("unsupported GNOME proxy mode %q", mode)
	}
}

func GetProxySettings(ctx context.Context) (*ProxySettings, error) { return GetSystemProxy(ctx) }
func SetProxySettings(ctx context.Context, settings ProxySettings) error {
	return SetSystemProxy(ctx, &settings)
}
func DisableSystemProxy(ctx context.Context) error { return SetSystemProxy(ctx, &ProxySettings{}) }
func DisableProxy(ctx context.Context) error       { return DisableSystemProxy(ctx) }
