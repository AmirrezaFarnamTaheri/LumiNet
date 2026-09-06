// Package linux manages Linux desktop payloads and system proxy configuration.
package linux

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// PayloadFormat defines how an HTTP payload is structured for proxy transport.
type PayloadFormat struct {
	// Template is the raw payload template with {HOST} and {PORT} substitution markers.
	Template string
	// Name is a human-readable label (e.g. "WebSocket", "HTTP Upgrade").
	Name string
}

// CommonPayloadFormats provides standard formats used in HTTP-based proxy transports.
var CommonPayloadFormats = []PayloadFormat{
	{Name: "HTTP Upgrade", Template: "GET / HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"},
	{Name: "CONNECT", Template: "CONNECT {HOST}:{PORT} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n\r\n"},
	{Name: "POST", Template: "POST / HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 0\r\n\r\n"},
}

// PayloadEditor handles HTTP payload formatting for Linux proxy clients,
// GNOME/KDE system proxy configuration, and process resource limits.
type PayloadEditor struct {
	// Format is the active payload format.
	Format PayloadFormat
}

func NewPayloadEditor() *PayloadEditor {
	return &PayloadEditor{Format: CommonPayloadFormats[0]}
}

// Render substitutes {HOST} and {PORT} in the payload template.
func (p *PayloadEditor) Render(host string, port int) string {
	out := strings.ReplaceAll(p.Format.Template, "{HOST}", host)
	out = strings.ReplaceAll(out, "{PORT}", fmt.Sprintf("%d", port))
	return out
}

// SetGNOMEProxy configures GNOME system proxy via gsettings.
// mode: "manual" or "none".
func (p *PayloadEditor) SetGNOMEProxy(host string, port int, mode string) error {
	cmds := [][]string{
		{"gsettings", "set", "org.gnome.system.proxy", "mode", mode},
	}
	if mode == "manual" {
		cmds = append(cmds,
			[]string{"gsettings", "set", "org.gnome.system.proxy.http", "host", host},
			[]string{"gsettings", "set", "org.gnome.system.proxy.http", "port", fmt.Sprintf("%d", port)},
			[]string{"gsettings", "set", "org.gnome.system.proxy.https", "host", host},
			[]string{"gsettings", "set", "org.gnome.system.proxy.https", "port", fmt.Sprintf("%d", port)},
		)
	}
	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("PayloadEditor.SetGNOMEProxy: %s: %w (%s)", args[0], err, strings.TrimSpace(string(out)))
		}
	}
	slog.Info("PayloadEditor: GNOME proxy configured", "host", host, "port", port, "mode", mode)
	return nil
}

// SetKDEProxy configures KDE system proxy via kwriteconfig5.
func (p *PayloadEditor) SetKDEProxy(host string, port int, enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	cmds := [][]string{
		{"kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", value},
		{"kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", fmt.Sprintf("http://%s:%d", host, port)},
	}
	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("PayloadEditor.SetKDEProxy: %s: %w (%s)", args[0], err, strings.TrimSpace(string(out)))
		}
	}
	slog.Info("PayloadEditor: KDE proxy configured", "host", host, "port", port, "enabled", enabled)
	return nil
}

// SaveFormat writes the current format template to a file.
func (p *PayloadEditor) SaveFormat(path string) error {
	if err := os.WriteFile(path, []byte(p.Format.Template), 0o644); err != nil {
		return fmt.Errorf("PayloadEditor.SaveFormat: %w", err)
	}
	slog.Info("PayloadEditor: format saved", "path", path)
	return nil
}
