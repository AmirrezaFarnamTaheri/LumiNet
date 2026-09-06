// Package hiddify provides bridging and orchestration for the hiddify-app FFI and Core.
// Ported from: Hiddify-Manager
// Target path: server/internal/hiddify/manager_haproxy.go
package hiddify

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"text/template"
)

// HAProxyConfig represents the configuration variables for HAProxy templating.
type HAProxyConfig struct {
	Timeout   string
	SniDomain string
	RealitySN string
}

// ManagerHAProxy orchestrates the HAProxy TCP load balancing and XTLS REALITY rendering.
type ManagerHAProxy struct {
	configPath string
	template   string
}

// NewManagerHAProxy initializes the HAProxy manager.
func NewManagerHAProxy(configPath string) *ManagerHAProxy {
	// Jinja2-rendered XTLS REALITY configuration equivalent (using Go text/template)
	tpl := `
global
    log /dev/log local0
    maxconn 2048

defaults
    log global
    mode tcp
    option tcplog
    timeout connect 5s
    timeout client {{.Timeout}}
    timeout server {{.Timeout}}

frontend ft_reality
    bind *:443
    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }
    
    # XTLS REALITY logic
    use_backend bk_xtls if { req_ssl_sni -i {{.RealitySN}} }
    default_backend bk_decoy

backend bk_xtls
    server local_xray 127.0.0.1:10001 send-proxy

backend bk_decoy
    server remote_decoy {{.SniDomain}}:443 ssl verify none
`
	return &ManagerHAProxy{
		configPath: configPath,
		template:   tpl,
	}
}

// RenderConfig renders the extended tunnel timeouts (1h) and XTLS REALITY configurations.
func (m *ManagerHAProxy) RenderConfig(sni, realitySN string) error {
	t, err := template.New("haproxy").Parse(m.template)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	cfg := HAProxyConfig{
		Timeout:   "1h", // Extended tunnel timeout
		SniDomain: sni,
		RealitySN: realitySN,
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, cfg); err != nil {
		return fmt.Errorf("failed to render haproxy config: %w", err)
	}

	if err := os.WriteFile(m.configPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write haproxy config: %w", err)
	}

	log.Printf("HAProxy XTLS REALITY config written to %s", m.configPath)
	return nil
}

// Reload reloads the HAProxy daemon.
func (m *ManagerHAProxy) Reload() error {
	cmd := exec.Command("systemctl", "reload", "haproxy")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload haproxy: %w", err)
	}
	return nil
}
