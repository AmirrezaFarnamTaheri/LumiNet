// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: envoy-main
// Target path: server/internal/proxy/envoy_proxy.go

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

// EnvoyProxy coordinates the dynamic configuration generation and process execution of the Envoy Proxy sidecar.
type EnvoyProxy struct {
	mu         sync.Mutex
	AdminPort  int
	ListenPort int
	Upstream   string // Target upstream server address (e.g. 127.0.0.1:8080)
	running    bool
	cmd        *exec.Cmd
	cancelFunc context.CancelFunc
}

// NewEnvoyProxy instantiates a new EnvoyProxy.
func NewEnvoyProxy() *EnvoyProxy {
	return &EnvoyProxy{
		AdminPort:  9901,
		ListenPort: 10000,
		Upstream:   "127.0.0.1:8080",
	}
}

// GenerateConfig writes a minimal bootstrap YAML configuration file for Envoy.
func (e *EnvoyProxy) GenerateConfig(outputPath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	yamlContent := fmt.Sprintf(`
admin:
  address:
    socket_address: { address: 127.0.0.1, port_value: %d }

static_resources:
  listeners:
  - name: ingress_listener
    address:
      socket_address: { address: 0.0.0.0, port_value: %d }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route: { cluster: local_upstream }
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: local_upstream
    connect_timeout: 0.25s
    type: LOGICAL_DNS
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: local_upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: { address: %s }
`, e.AdminPort, e.ListenPort, e.Upstream)

	return ioutil.WriteFile(outputPath, []byte(yamlContent), 0644)
}

// StartEnvoy starts the Envoy process in a background context using the specified configuration path.
func (e *EnvoyProxy) StartEnvoy(ctx context.Context, binaryPath string, configPath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return fmt.Errorf("envoy is already running")
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("envoy config file not found: %s", configPath)
	}

	procCtx, cancel := context.WithCancel(ctx)
	e.cancelFunc = cancel

	cmd := exec.CommandContext(procCtx, binaryPath, "-c", configPath)
	err := cmd.Start()
	if err != nil {
		cancel()
		return err
	}

	e.cmd = cmd
	e.running = true
	log.Printf("EnvoyProxy: Established Envoy sidecar on port %d forwarding to %s (Admin port: %d)", e.ListenPort, e.Upstream, e.AdminPort)

	// Monitor process termination in background
	go func() {
		_ = cmd.Wait()
		e.mu.Lock()
		e.running = false
		e.cmd = nil
		e.mu.Unlock()
		slog.Info("EnvoyProxy", "status", "Envoy process stopped")
	}()

	return nil
}

// StopEnvoy gracefully stops the Envoy sidecar.
func (e *EnvoyProxy) StopEnvoy() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return nil
	}

	if e.cancelFunc != nil {
		e.cancelFunc()
	}
	e.running = false
	e.cmd = nil
	return nil
}

// Configure implements the legacy entry trigger.
func (e *EnvoyProxy) Configure() {
	// Diagnostic stub
}
