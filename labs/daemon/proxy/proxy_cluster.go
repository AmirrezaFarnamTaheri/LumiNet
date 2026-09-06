// Package proxy provides proxy routing and configuration utilities.
// Ported from: karing-main app/modules/proxy_cluster.dart
// Target path: server/internal/proxy/proxy_cluster.go

package proxy

import (
	"fmt"
	"net"
	"sync"
)

// ProxyClusterNode represents an allocated port for a specific outbound tag.
type ProxyClusterNode struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Port    int    `json:"port"`
	Latency string `json:"latency,omitempty"`
}

// ProxyClusterManager allocates and tracks mixed inbounds for specific outbounds.
type ProxyClusterManager struct {
	mu          sync.Mutex
	ClusterHost string
	StartPort   int
	TagPorts    map[string]int
}

// NewProxyClusterManager instantiates a new ProxyClusterManager.
func NewProxyClusterManager(host string, startPort int) *ProxyClusterManager {
	return &ProxyClusterManager{
		ClusterHost: host,
		StartPort:   startPort,
		TagPorts:    make(map[string]int),
	}
}

// InboundConfig represents the sing-box mixed inbound structure.
type InboundConfig struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen"`
	ListenPort int    `json:"listen_port"`
}

// RouteRuleConfig represents the sing-box route rule structure.
type RouteRuleConfig struct {
	Inbound  []string `json:"inbound"`
	Outbound string   `json:"outbound"`
}

// AllocateCluster maps each outbound tag to a dynamic local port and returns the configs.
func (m *ProxyClusterManager) AllocateCluster(outbounds []ProxyClusterNode) ([]InboundConfig, []RouteRuleConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var inbounds []InboundConfig
	var rules []RouteRuleConfig

	currentPort := m.StartPort

	for _, outbound := range outbounds {
		port, ok := m.TagPorts[outbound.Name]
		if !ok {
			// Find an available port starting from currentPort
			for {
				addr := fmt.Sprintf("%s:%d", m.ClusterHost, currentPort)
				ln, err := net.Listen("tcp", addr)
				if err == nil {
					ln.Close()
					port = currentPort
					m.TagPorts[outbound.Name] = port
					currentPort++
					break
				}
				currentPort++
				if currentPort > 65535 {
					return nil, nil, fmt.Errorf("port allocation space exhausted")
				}
			}
		}

		inbounds = append(inbounds, InboundConfig{
			Type:       "mixed",
			Tag:        fmt.Sprintf("mixed_in:cluster:%s", outbound.Name),
			Listen:     m.ClusterHost,
			ListenPort: port,
		})

		rules = append(rules, RouteRuleConfig{
			Inbound:  []string{fmt.Sprintf("mixed_in:cluster:%s", outbound.Name)},
			Outbound: outbound.Name,
		})
	}

	return inbounds, rules, nil
}
