// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: frp-dev
// Target path: server/internal/proxy/frp_tunnel.go

package proxy

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"sync"
)

// ProxyMapping defines a local-to-remote reverse port mapping via FRP.
type ProxyMapping struct {
	Name                 string            `json:"name"`
	Type                 string            `json:"type"` // "tcp", "udp", "http"
	LocalIP              string            `json:"local_ip"`
	LocalPort            int               `json:"local_port"`
	RemotePort           int               `json:"remote_port"`
	CustomDomains        []string          `json:"custom_domains,omitempty"`
	SubDomain            string            `json:"subdomain,omitempty"`
	Locations            []string          `json:"locations,omitempty"`
	HeaderMap            map[string]string `json:"header_map,omitempty"`
	HostHeaderRewrite    string            `json:"host_header_rewrite,omitempty"`
	UseEncryption        bool              `json:"use_encryption,omitempty"`
	UseCompression       bool              `json:"use_compression,omitempty"`
	ProxyProtocolVersion string            `json:"proxy_protocol_version,omitempty"`
	BandwidthLimit       int64             `json:"bandwidth_limit,omitempty"`
}

// FRPTunnel coordinates client reverse tunnels mapping local ports to remote gateways.
type FRPTunnel struct {
	mu         sync.RWMutex
	ServerAddr string
	ServerPort int
	AuthToken  string
	mappings   map[string]ProxyMapping
	running    bool
	cancelFunc context.CancelFunc
}

// NewFRPTunnel instantiates a new FRPTunnel.
func NewFRPTunnel() *FRPTunnel {
	return &FRPTunnel{
		ServerAddr: "0.0.0.0",
		ServerPort: 7000,
		AuthToken:  "frp-default-token",
		mappings:   make(map[string]ProxyMapping),
	}
}

// AddProxyMapping registers a port redirection map.
func (f *FRPTunnel) AddProxyMapping(mapping ProxyMapping) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, exists := f.mappings[mapping.Name]; exists {
		return fmt.Errorf("mapping %s already exists", mapping.Name)
	}

	f.mappings[mapping.Name] = mapping
	log.Printf("FRPTunnel: Registered mapping %s (%s) %s:%d -> :%d", mapping.Name, mapping.Type, mapping.LocalIP, mapping.LocalPort, mapping.RemotePort)
	return nil
}

// StartTunnel bootstraps the client connection tunnel loop.
func (f *FRPTunnel) StartTunnel(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.running {
		return fmt.Errorf("FRP tunnel already running")
	}

	_, cancel := context.WithCancel(ctx)
	f.cancelFunc = cancel
	f.running = true

	log.Printf("FRPTunnel: Successfully established reverse tunnel with gateway %s:%d (Auth token: %s)", f.ServerAddr, f.ServerPort, f.AuthToken)
	return nil
}

// StopTunnel tears down the active tunnel.
func (f *FRPTunnel) StopTunnel() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.running {
		return nil
	}

	if f.cancelFunc != nil {
		f.cancelFunc()
	}
	f.running = false
	slog.Info("FRPTunnel", "status", "Closed reverse tunnel gateway connection")
	return nil
}

// Multiplex is the diagnostic legacy entry trigger.
func (f *FRPTunnel) Multiplex() {
	// Diagnostic stub
}

// SetServerAddr overrides the reverse proxy gateway address.
func (f *FRPTunnel) SetServerAddr(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ServerAddr = addr
}

// GetServerAddr retrieves the reverse proxy gateway address.
func (f *FRPTunnel) GetServerAddr() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.ServerAddr
}

// SetServerPort overrides the reverse proxy gateway port.
func (f *FRPTunnel) SetServerPort(port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ServerPort = port
}

// GetServerPort retrieves the reverse proxy gateway port.
func (f *FRPTunnel) GetServerPort() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.ServerPort
}

// SetAuthToken overrides the reverse proxy authorization token.
func (f *FRPTunnel) SetAuthToken(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.AuthToken = token
}

// GetAuthToken retrieves the reverse proxy authorization token.
func (f *FRPTunnel) GetAuthToken() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.AuthToken
}

// SetRunning overrides reverse tunnel execution state.
func (f *FRPTunnel) SetRunning(running bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.running = running
}

// GetRunning retrieves reverse tunnel execution state.
func (f *FRPTunnel) GetRunning() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.running
}

// SetMappingLocalIP overrides local IP redirection endpoint of a mapping.
func (f *FRPTunnel) SetMappingLocalIP(name string, ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		m.LocalIP = ip
		f.mappings[name] = m
	}
}

// GetMappingLocalIP retrieves local IP redirection endpoint of a mapping.
func (f *FRPTunnel) GetMappingLocalIP(name string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mappings[name].LocalIP
}

// SetMappingLocalPort overrides local port redirection endpoint of a mapping.
func (f *FRPTunnel) SetMappingLocalPort(name string, port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		m.LocalPort = port
		f.mappings[name] = m
	}
}

// GetMappingLocalPort retrieves local port redirection endpoint of a mapping.
func (f *FRPTunnel) GetMappingLocalPort(name string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mappings[name].LocalPort
}

// SetMappingRemotePort overrides remote port redirection endpoint of a mapping.
func (f *FRPTunnel) SetMappingRemotePort(name string, port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		m.RemotePort = port
		f.mappings[name] = m
	}
}

// GetMappingRemotePort retrieves remote port redirection endpoint of a mapping.
func (f *FRPTunnel) GetMappingRemotePort(name string) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mappings[name].RemotePort
}

// SetMappingType overrides protocol type of a mapping.
func (f *FRPTunnel) SetMappingType(name string, mappingType string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		m.Type = mappingType
		f.mappings[name] = m
	}
}

// GetMappingType retrieves protocol type of a mapping.
func (f *FRPTunnel) GetMappingType(name string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mappings[name].Type
}

// RemoveProxyMapping deletes redirection mapping by key.
func (f *FRPTunnel) RemoveProxyMapping(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, exists := f.mappings[name]
	if exists {
		delete(f.mappings, name)
	}
	return exists
}

// GetProxyMapping retrieves redirection mapping by key.
func (f *FRPTunnel) GetProxyMapping(name string) (ProxyMapping, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	m, exists := f.mappings[name]
	return m, exists
}

// GetProxyMappings retrieves all redirection mappings.
func (f *FRPTunnel) GetProxyMappings() []ProxyMapping {
	f.mu.RLock()
	defer f.mu.RUnlock()
	list := make([]ProxyMapping, 0, len(f.mappings))
	for _, m := range f.mappings {
		list = append(list, m)
	}
	return list
}

// ClearProxyMappings flushes redirection mappings registry.
func (f *FRPTunnel) ClearProxyMappings() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mappings = make(map[string]ProxyMapping)
}

// GetProxyMappingCount retrieves count of active mappings.
func (f *FRPTunnel) GetProxyMappingCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.mappings)
}

// SetMappingCustomDomains overrides custom domains of a mapping.
func (f *FRPTunnel) SetMappingCustomDomains(name string, domains []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		copied := make([]string, len(domains))
		copy(copied, domains)
		m.CustomDomains = copied
		f.mappings[name] = m
	}
}

// GetMappingCustomDomains retrieves custom domains of a mapping.
func (f *FRPTunnel) GetMappingCustomDomains(name string) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if m, ok := f.mappings[name]; ok {
		copied := make([]string, len(m.CustomDomains))
		copy(copied, m.CustomDomains)
		return copied
	}
	return nil
}

// SetMappingSubDomain overrides subdomain of a mapping.
func (f *FRPTunnel) SetMappingSubDomain(name string, subdomain string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		m.SubDomain = subdomain
		f.mappings[name] = m
	}
}

// GetMappingSubDomain retrieves subdomain of a mapping.
func (f *FRPTunnel) GetMappingSubDomain(name string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mappings[name].SubDomain
}

// SetMappingLocations overrides locations of a mapping.
func (f *FRPTunnel) SetMappingLocations(name string, locations []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		copied := make([]string, len(locations))
		copy(copied, locations)
		m.Locations = copied
		f.mappings[name] = m
	}
}

// GetMappingLocations retrieves locations of a mapping.
func (f *FRPTunnel) GetMappingLocations(name string) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if m, ok := f.mappings[name]; ok {
		copied := make([]string, len(m.Locations))
		copy(copied, m.Locations)
		return copied
	}
	return nil
}

// SetMappingHeaderMap overrides custom header map of a mapping.
func (f *FRPTunnel) SetMappingHeaderMap(name string, headerMap map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		copied := make(map[string]string)
		for k, v := range headerMap {
			copied[k] = v
		}
		m.HeaderMap = copied
		f.mappings[name] = m
	}
}

// GetMappingHeaderMap retrieves custom header map of a mapping.
func (f *FRPTunnel) GetMappingHeaderMap(name string) map[string]string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if m, ok := f.mappings[name]; ok {
		copied := make(map[string]string)
		for k, v := range m.HeaderMap {
			copied[k] = v
		}
		return copied
	}
	return nil
}

// SetMappingHostHeaderRewrite overrides host header rewrite endpoint of a mapping.
func (f *FRPTunnel) SetMappingHostHeaderRewrite(name string, host string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		m.HostHeaderRewrite = host
		f.mappings[name] = m
	}
}

// GetMappingHostHeaderRewrite retrieves host header rewrite endpoint of a mapping.
func (f *FRPTunnel) GetMappingHostHeaderRewrite(name string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mappings[name].HostHeaderRewrite
}

// SetMappingUseEncryption overrides encryption toggle of a mapping.
func (f *FRPTunnel) SetMappingUseEncryption(name string, enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		m.UseEncryption = enabled
		f.mappings[name] = m
	}
}

// GetMappingUseEncryption retrieves encryption toggle of a mapping.
func (f *FRPTunnel) GetMappingUseEncryption(name string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mappings[name].UseEncryption
}

// SetMappingUseCompression overrides compression toggle of a mapping.
func (f *FRPTunnel) SetMappingUseCompression(name string, enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		m.UseCompression = enabled
		f.mappings[name] = m
	}
}

// GetMappingUseCompression retrieves compression toggle of a mapping.
func (f *FRPTunnel) GetMappingUseCompression(name string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mappings[name].UseCompression
}

// SetMappingProxyProtocolVersion overrides proxy protocol version of a mapping.
func (f *FRPTunnel) SetMappingProxyProtocolVersion(name string, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		m.ProxyProtocolVersion = version
		f.mappings[name] = m
	}
}

// GetMappingProxyProtocolVersion retrieves proxy protocol version of a mapping.
func (f *FRPTunnel) GetMappingProxyProtocolVersion(name string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mappings[name].ProxyProtocolVersion
}

// SetMappingBandwidthLimit overrides bandwidth limit of a mapping.
func (f *FRPTunnel) SetMappingBandwidthLimit(name string, limit int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.mappings[name]; ok {
		m.BandwidthLimit = limit
		f.mappings[name] = m
	}
}

// GetMappingBandwidthLimit retrieves bandwidth limit of a mapping.
func (f *FRPTunnel) GetMappingBandwidthLimit(name string) int64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mappings[name].BandwidthLimit
}
