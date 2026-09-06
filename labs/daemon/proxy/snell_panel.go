// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: snell-panel-refactor-hono-heroui
// Target path: server/internal/proxy/snell_panel.go

package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// SnellPanel manages Snell proxy version resolution and subscribe routes (from index.ts).
type SnellPanel struct {
	mu       sync.RWMutex
	versions []string
	nodes    map[string]SnellNode
	settings map[string]string
}

// SnellNode defines a Snell server configuration (from schema.ts).
type SnellNode struct {
	Name         string `json:"name"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	PSK          string `json:"psk"`
	Version      string `json:"version"` // Snell protocol version (e.g. "4", "5", "6")
	Status       string `json:"status"`  // "pending" | "active"
	CountryCode  string `json:"country_code"`
	ISP          string `json:"isp"`
	ASN          int    `json:"asn"`
	TFO          bool   `json:"tfo"`
	Enabled      bool   `json:"enabled"`
	CreatedAt    int64  `json:"created_at"`
	RegisteredAt int64  `json:"registered_at"`
}

// NewSnellPanel initializes a new SnellPanel.
func NewSnellPanel() *SnellPanel {
	return &SnellPanel{
		versions: []string{"v1.1.1", "v2.0.0", "v3.0.0", "v4.0.0", "v5.0.1", "v6.0.0b4"},
		nodes:    make(map[string]SnellNode),
		settings: make(map[string]string),
	}
}

// ResolveVersions returns active Snell versions (from index.ts).
func (s *SnellPanel) ResolveVersions() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]string, len(s.versions))
	copy(copied, s.versions)
	return copied
}

// AddNode registers a Snell node config (from index.ts).
func (s *SnellPanel) AddNode(node SnellNode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[node.Name] = node
}

// RemoveNode deletes registered Snell node by name.
func (s *SnellPanel) RemoveNode(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.nodes, name)
}

// GenerateSubscribeConfig returns Clash or Surge formatted proxy profiles (from index.ts).
func (s *SnellPanel) GenerateSubscribeConfig(format string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var builder strings.Builder

	if strings.EqualFold(format, "surge") {
		for name, node := range s.nodes {
			version := node.Version
			if version == "" {
				version = "4"
			}
			builder.WriteString(fmt.Sprintf("%s = snell, %s, %d, psk=%s, version=%s\n", name, node.Host, node.Port, node.PSK, version))
		}
		return builder.String(), nil
	}

	// Default to Clash format
	type ClashProxy struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Server  string `json:"server"`
		Port    int    `json:"port"`
		Psk     string `json:"psk"`
		Version string `json:"version"`
	}

	var proxies []ClashProxy
	for name, node := range s.nodes {
		version := node.Version
		if version == "" {
			version = "4"
		}
		proxies = append(proxies, ClashProxy{
			Name:    name,
			Type:    "snell",
			Server:  node.Host,
			Port:    node.Port,
			Psk:     node.PSK,
			Version: version,
		})
	}

	data, err := json.MarshalIndent(proxies, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// SetSetting overrides the snell panel settings map key value.
func (s *SnellPanel) SetSetting(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings[key] = value
}

// GetSetting retrieves the snell panel settings map key value.
func (s *SnellPanel) GetSetting(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings[key]
}

// ClearSettings resets the snell panel settings map registry.
func (s *SnellPanel) ClearSettings() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = make(map[string]string)
}

// GetSettingsCount returns total items in snell settings map registry.
func (s *SnellPanel) GetSettingsCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.settings)
}

// AddSnellNode registers a new Snell node configuration (from schema.ts).
func (s *SnellPanel) AddSnellNode(node SnellNode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[node.Name] = node
}

// RemoveSnellNode deletes a Snell node configuration.
func (s *SnellPanel) RemoveSnellNode(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.nodes[name]
	if exists {
		delete(s.nodes, name)
	}
	return exists
}

// GetSnellNode retrieves a single Snell node configuration.
func (s *SnellPanel) GetSnellNode(name string) (SnellNode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, exists := s.nodes[name]
	return node, exists
}

// GetSnellNodes retrieves all registered Snell node configurations.
func (s *SnellPanel) GetSnellNodes() []SnellNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]SnellNode, 0, len(s.nodes))
	for _, node := range s.nodes {
		list = append(list, node)
	}
	return list
}

// ClearSnellNodes resets Snell node registry.
func (s *SnellPanel) ClearSnellNodes() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes = make(map[string]SnellNode)
}

// GetSnellNodeCount returns total items in Snell node registry.
func (s *SnellPanel) GetSnellNodeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes)
}

// SetNodeHost overrides host endpoint of a Snell node.
func (s *SnellPanel) SetNodeHost(name, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.Host = host
		s.nodes[name] = n
	}
}

// GetNodeHost retrieves host endpoint of a Snell node.
func (s *SnellPanel) GetNodeHost(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].Host
}

// SetNodePort overrides port of a Snell node.
func (s *SnellPanel) SetNodePort(name string, port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.Port = port
		s.nodes[name] = n
	}
}

// GetNodePort retrieves port of a Snell node.
func (s *SnellPanel) GetNodePort(name string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].Port
}

// SetNodePSK overrides preshared key of a Snell node.
func (s *SnellPanel) SetNodePSK(name, psk string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.PSK = psk
		s.nodes[name] = n
	}
}

// GetNodePSK retrieves preshared key of a Snell node.
func (s *SnellPanel) GetNodePSK(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].PSK
}

// SetNodeVersion overrides version of a Snell node.
func (s *SnellPanel) SetNodeVersion(name, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.Version = version
		s.nodes[name] = n
	}
}

// GetNodeVersion retrieves version of a Snell node.
func (s *SnellPanel) GetNodeVersion(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].Version
}

// SetNodeStatus overrides status of a Snell node.
func (s *SnellPanel) SetNodeStatus(name, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.Status = status
		s.nodes[name] = n
	}
}

// GetNodeStatus retrieves status of a Snell node.
func (s *SnellPanel) GetNodeStatus(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].Status
}

// SetNodeCountryCode overrides country code of a Snell node.
func (s *SnellPanel) SetNodeCountryCode(name, countryCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.CountryCode = countryCode
		s.nodes[name] = n
	}
}

// GetNodeCountryCode retrieves country code of a Snell node.
func (s *SnellPanel) GetNodeCountryCode(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].CountryCode
}

// SetNodeISP overrides ISP of a Snell node.
func (s *SnellPanel) SetNodeISP(name, isp string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.ISP = isp
		s.nodes[name] = n
	}
}

// GetNodeISP retrieves ISP of a Snell node.
func (s *SnellPanel) GetNodeISP(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].ISP
}

// SetNodeASN overrides ASN of a Snell node.
func (s *SnellPanel) SetNodeASN(name string, asn int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.ASN = asn
		s.nodes[name] = n
	}
}

// GetNodeASN retrieves ASN of a Snell node.
func (s *SnellPanel) GetNodeASN(name string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].ASN
}

// SetNodeTFO overrides TCP Fast Open of a Snell node.
func (s *SnellPanel) SetNodeTFO(name string, tfo bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.TFO = tfo
		s.nodes[name] = n
	}
}

// GetNodeTFO retrieves TCP Fast Open of a Snell node.
func (s *SnellPanel) GetNodeTFO(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].TFO
}

// SetNodeEnabled overrides enabled flag of a Snell node.
func (s *SnellPanel) SetNodeEnabled(name string, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.Enabled = enabled
		s.nodes[name] = n
	}
}

// GetNodeEnabled retrieves enabled flag of a Snell node.
func (s *SnellPanel) GetNodeEnabled(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].Enabled
}

// SetNodeCreatedAt overrides creation timestamp of a Snell node.
func (s *SnellPanel) SetNodeCreatedAt(name string, val int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.CreatedAt = val
		s.nodes[name] = n
	}
}

// GetNodeCreatedAt retrieves creation timestamp of a Snell node.
func (s *SnellPanel) GetNodeCreatedAt(name string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].CreatedAt
}

// SetNodeRegisteredAt overrides registration timestamp of a Snell node.
func (s *SnellPanel) SetNodeRegisteredAt(name string, val int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[name]; ok {
		n.RegisteredAt = val
		s.nodes[name] = n
	}
}

// GetNodeRegisteredAt retrieves registration timestamp of a Snell node.
func (s *SnellPanel) GetNodeRegisteredAt(name string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[name].RegisteredAt
}

// SetName overrides SnellNode name tag.
func (n *SnellNode) SetName(name string) {
	n.Name = name
}

// GetName retrieves SnellNode name tag.
func (n *SnellNode) GetName() string {
	return n.Name
}

// SetHost overrides SnellNode server endpoint host address.
func (n *SnellNode) SetHost(host string) {
	n.Host = host
}

// GetHost retrieves SnellNode server endpoint host address.
func (n *SnellNode) GetHost() string {
	return n.Host
}

// SetPort overrides SnellNode server endpoint host port.
func (n *SnellNode) SetPort(port int) {
	n.Port = port
}

// GetPort retrieves SnellNode server endpoint host port.
func (n *SnellNode) GetPort() int {
	return n.Port
}

// SetPSK overrides SnellNode server credentials auth psk.
func (n *SnellNode) SetPSK(psk string) {
	n.PSK = psk
}

// GetPSK retrieves SnellNode server credentials auth psk.
func (n *SnellNode) GetPSK() string {
	return n.PSK
}

// SetVersion overrides SnellNode protocol schema version.
func (n *SnellNode) SetVersion(v string) {
	n.Version = v
}

// GetVersion retrieves SnellNode protocol schema version.
func (n *SnellNode) GetVersion() string {
	return n.Version
}

// SetStatus overrides SnellNode health check state.
func (n *SnellNode) SetStatus(status string) {
	n.Status = status
}

// GetStatus retrieves SnellNode health check state.
func (n *SnellNode) GetStatus() string {
	return n.Status
}

// SetCountryCode overrides SnellNode geo location region.
func (n *SnellNode) SetCountryCode(cc string) {
	n.CountryCode = cc
}

// GetCountryCode retrieves SnellNode geo location region.
func (n *SnellNode) GetCountryCode() string {
	return n.CountryCode
}

// SetISP overrides SnellNode internet provider name.
func (n *SnellNode) SetISP(isp string) {
	n.ISP = isp
}

// GetISP retrieves SnellNode internet provider name.
func (n *SnellNode) GetISP() string {
	return n.ISP
}

// SetASN overrides SnellNode network system asn routing tag.
func (n *SnellNode) SetASN(asn int) {
	n.ASN = asn
}

// GetASN retrieves SnellNode network system asn routing tag.
func (n *SnellNode) GetASN() int {
	return n.ASN
}

// SetTFO overrides SnellNode TCP Fast Open indicator.
func (n *SnellNode) SetTFO(tfo bool) {
	n.TFO = tfo
}

// GetTFO retrieves SnellNode TCP Fast Open indicator.
func (n *SnellNode) GetTFO() bool {
	return n.TFO
}

// SetEnabled overrides SnellNode subscription generator include toggle.
func (n *SnellNode) SetEnabled(enabled bool) {
	n.Enabled = enabled
}

// GetEnabled retrieves SnellNode subscription generator include toggle.
func (n *SnellNode) GetEnabled() bool {
	return n.Enabled
}

// SetCreatedAt overrides SnellNode registry creation timestamp.
func (n *SnellNode) SetCreatedAt(t int64) {
	n.CreatedAt = t
}

// GetCreatedAt retrieves SnellNode registry creation timestamp.
func (n *SnellNode) GetCreatedAt() int64 {
	return n.CreatedAt
}

// SetRegisteredAt overrides SnellNode registry activity activation timestamp.
func (n *SnellNode) SetRegisteredAt(t int64) {
	n.RegisteredAt = t
}

// GetRegisteredAt retrieves SnellNode registry activity activation timestamp.
func (n *SnellNode) GetRegisteredAt() int64 {
	return n.RegisteredAt
}
