package proxyconfig

import (
	"encoding/json"
	"errors"
	"sync"
)

type TlsCertificateBinding struct {
	CertPath      string   `json:"cert"`
	KeyPath       string   `json:"key"`
	SniDomain     string   `json:"sni"`
	AlpnProtocols []string `json:"alpn"`
}

type TcpOptions struct {
	FastOpen bool `json:"fast_open"`
}

type ServerConfigJSON struct {
	RunType    string                `json:"run_type"`
	LocalAddr  string                `json:"local_addr"`
	LocalPort  uint16                `json:"local_port"`
	RemoteAddr string                `json:"remote_addr"`
	RemotePort uint16                `json:"remote_port"`
	Password   []string              `json:"password"`
	SSL        TlsCertificateBinding `json:"ssl"`
	TCP        TcpOptions            `json:"tcp"`
}

type ServerProvisionConfig struct {
	LocalAddr          string
	LocalPort          uint16
	RemoteFallbackAddr string
	RemoteFallbackPort uint16
	Passwords          []string
	TLS                TlsCertificateBinding
	EnableFastOpen     bool
}

type AutomatedTlsServerConfigurator struct {
	servers map[string]*ServerProvisionConfig
	mu      sync.RWMutex
}

func NewAutomatedTlsServerConfigurator() *AutomatedTlsServerConfigurator {
	return &AutomatedTlsServerConfigurator{
		servers: make(map[string]*ServerProvisionConfig),
	}
}

func (c *AutomatedTlsServerConfigurator) RegisterServer(serverID string, cfg *ServerProvisionConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.servers[serverID] = cfg
}

func (c *AutomatedTlsServerConfigurator) GenerateJSON(serverID string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cfg, ok := c.servers[serverID]
	if !ok {
		return nil, errors.New("server not found")
	}

	payload := ServerConfigJSON{
		RunType:    "server",
		LocalAddr:  cfg.LocalAddr,
		LocalPort:  cfg.LocalPort,
		RemoteAddr: cfg.RemoteFallbackAddr,
		RemotePort: cfg.RemoteFallbackPort,
		Password:   cfg.Passwords,
		SSL:        cfg.TLS,
		TCP:        TcpOptions{FastOpen: cfg.EnableFastOpen},
	}

	return json.MarshalIndent(payload, "", "  ")
}
