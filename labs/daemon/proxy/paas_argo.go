// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: PaaS-vmess-trojan-argo-main
// Target path: server/internal/proxy/paas_argo.go

package proxy

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"sync"
)

// PaaSArgo handles cloud-native deployments of VMess/Trojan over Cloudflare Argo tunnels.
type PaaSArgo struct {
	mu          sync.Mutex
	TunnelToken string
	running     bool
	cmd         *exec.Cmd
	cancelFunc  context.CancelFunc
}

// NewPaaSArgo instantiates a new PaaSArgo instance.
func NewPaaSArgo() *PaaSArgo {
	return &PaaSArgo{
		TunnelToken: "default-argo-tunnel-token-here",
	}
}

// GenerateConfig creates a VLESS/VMess Cloudflare config file structure.
func (p *PaaSArgo) GenerateConfig(outputPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	yamlConfig := fmt.Sprintf(`
tunnel: %s
credentials-file: /root/.cloudflared/%s.json

ingress:
  - hostname: argo.luminet.proxy
    service: http://localhost:8080
  - service: http_status:404
`, p.TunnelToken, p.TunnelToken)

	return ioutil.WriteFile(outputPath, []byte(yamlConfig), 0644)
}

// StartTunnel runs the cloudflared process to route VMess/Trojan outbounds.
func (p *PaaSArgo) StartTunnel(ctx context.Context, binaryPath string, configPath string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("argo tunnel already running")
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("cloudflared config file not found: %s", configPath)
	}

	procCtx, cancel := context.WithCancel(ctx)
	p.cancelFunc = cancel

	cmd := exec.CommandContext(procCtx, binaryPath, "tunnel", "--config", configPath, "run")
	err := cmd.Start()
	if err != nil {
		cancel()
		return err
	}

	p.cmd = cmd
	p.running = true
	log.Printf("PaaSArgo: Cloudflared argo tunnel established utilizing config: %s", configPath)

	go func() {
		_ = cmd.Wait()
		p.mu.Lock()
		p.running = false
		p.cmd = nil
		p.mu.Unlock()
		slog.Info("PaaSArgo", "status", "Cloudflared process stopped")
	}()

	return nil
}

// StopTunnel stops the cloudflared argo tunnel process.
func (p *PaaSArgo) StopTunnel() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	if p.cancelFunc != nil {
		p.cancelFunc()
	}
	p.running = false
	p.cmd = nil
	return nil
}

// Connect implements the legacy entry trigger.
func (p *PaaSArgo) Connect() {
	// Diagnostic stub
}
