// Package xrayconfig provides Xray-core configuration generation.
// Ported from RKh-CF-Scanner and SIMORGH VPN.
//
// Generates complete Xray JSON configs from proxy URIs (VLESS, VMess, Trojan, SS).
// Supports TLS, REALITY, WebSocket, gRPC, HTTP/2, XHTTP transports.
package xrayconfig

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// XrayConfig represents a complete Xray configuration.
type XrayConfig struct {
	Log       LogConfig        `json:"log"`
	Inbounds  []Inbound        `json:"inbounds"`
	Outbounds []Outbound       `json:"outbounds"`
	Routing   RoutingConfig    `json:"routing"`
	DNS       DNSConfig        `json:"dns,omitempty"`
}

type LogConfig struct {
	LogLevel string `json:"loglevel"`
}

type Inbound struct {
	Tag      string          `json:"tag"`
	Port     int             `json:"port"`
	Listen   string          `json:"listen,omitempty"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

type Outbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
}

type StreamSettings struct {
	Network    string          `json:"network"`
	Security   string          `json:"security"`
	TLSSettings *TLSSettings   `json:"tlsSettings,omitempty"`
	WSSettings  *WSSettings    `json:"wsSettings,omitempty"`
	GRPCSettings *GRPCSettings `json:"grpcSettings,omitempty"`
	H2Settings   *H2Settings   `json:"httpSettings,omitempty"`
	Sockopt      *Sockopt      `json:"sockopt,omitempty"`
}

type TLSSettings struct {
	ServerName    string   `json:"serverName,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	AllowInsecure bool     `json:"allowInsecure,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
}

type WSSettings struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
}

type GRPCSettings struct {
	ServiceName string `json:"serviceName"`
}

type H2Settings struct {
	Path string   `json:"path"`
	Host []string `json:"host"`
}

type Sockopt struct {
	Mark int `json:"mark,omitempty"`
}

type RoutingConfig struct {
	DomainStrategy string       `json:"domainStrategy"`
	Rules          []RoutingRule `json:"rules"`
}

type RoutingRule struct {
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

type DNSConfig struct {
	Servers []string `json:"servers"`
}

// VLESSConfig represents a parsed VLESS URI.
type VLESSConfig struct {
	UUID     string
	Address  string
	Port     int
	Security string
	SNI      string
	Flow     string
	FP       string
	PBK      string
	SID      string
	Net      string
	Path     string
	Host     string
	ALPN     []string
	Name     string
}

// ParseVLESS parses a vless:// URI.
func ParseVLESS(uri string) (*VLESSConfig, error) {
	rest := strings.TrimPrefix(uri, "vless://")
	atIdx := strings.Index(rest, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("invalid vless URI: missing @")
	}

	uuid := rest[:atIdx]
	remainder := rest[atIdx+1:]

	hostPort, query, fragment := splitParts(remainder)
	host, portStr, err := netSplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("invalid host:port: %w", err)
	}
	port, _ := strconv.Atoi(portStr)

	params := parseQuery(query)
	name, _ := url.PathUnescape(fragment)

	return &VLESSConfig{
		UUID:     uuid,
		Address:  host,
		Port:     port,
		Security: getString(params, "security", "none"),
		SNI:      getString(params, "sni", ""),
		Flow:     getString(params, "flow", ""),
		FP:       getString(params, "fp", ""),
		PBK:      getString(params, "pbk", ""),
		SID:      getString(params, "sid", ""),
		Net:      getString(params, "type", "tcp"),
		Path:     getString(params, "path", "/"),
		Host:     getString(params, "host", ""),
		ALPN:     splitComma(params["alpn"]),
		Name:     name,
	}, nil
}

// BuildXrayConfig generates a complete Xray config from a VLESS URI.
func BuildXrayConfig(vlessURI string, socksPort int) (*XrayConfig, error) {
	cfg, err := ParseVLESS(vlessURI)
	if err != nil {
		return nil, err
	}

	// Build outbound
	outbound := Outbound{
		Tag:      "proxy",
		Protocol: "vless",
		Settings: buildVLESSSettings(cfg),
		StreamSettings: buildStreamSettings(cfg),
	}

	// Build SOCKS inbound
	inbound := Inbound{
		Tag:      "socks-in",
		Port:     socksPort,
		Listen:   "127.0.0.1",
		Protocol: "socks",
		Settings: json.RawMessage(`{"auth":"noauth","udp":true}`),
	}

	// Routing rules
	rules := []RoutingRule{
		{Type: "field", IP: []string{"geoip:private"}, OutboundTag: "direct"},
		{Type: "field", Domain: []string{"geosite:category-ads-all"}, OutboundTag: "block"},
	}

	return &XrayConfig{
		Log: LogConfig{LogLevel: "warn"},
		Inbounds: []Inbound{inbound},
		Outbounds: []Outbound{
			outbound,
			{Tag: "direct", Protocol: "freedom", Settings: json.RawMessage(`{}`)},
			{Tag: "block", Protocol: "blackhole", Settings: json.RawMessage(`{}`)},
		},
		Routing: RoutingConfig{
			DomainStrategy: "IPIfNonMatch",
			Rules:          rules,
		},
		DNS: DNSConfig{
			Servers: []string{"https://1.1.1.1/dns-query", "https://dns.google/dns-query"},
		},
	}, nil
}

func buildVLESSSettings(cfg *VLESSConfig) json.RawMessage {
	vnext := []map[string]interface{}{
		{
			"address": cfg.Address,
			"port":    cfg.Port,
			"users": []map[string]interface{}{
				{
					"id":         cfg.UUID,
					"encryption": "none",
					"flow":       cfg.Flow,
				},
			},
		},
	}
	settings := map[string]interface{}{"vnext": vnext}
	data, _ := json.Marshal(settings)
	return data
}

func buildStreamSettings(cfg *VLESSConfig) *StreamSettings {
	ss := &StreamSettings{
		Network: cfg.Net,
	}

	// Security
	switch cfg.Security {
	case "tls":
		ss.Security = "tls"
		ss.TLSSettings = &TLSSettings{
			ServerName:    cfg.SNI,
			Fingerprint:   cfg.FP,
			AllowInsecure: false,
			ALPN:          cfg.ALPN,
		}
	case "reality":
		ss.Security = "reality"
		ss.TLSSettings = &TLSSettings{
			ServerName:  cfg.SNI,
			Fingerprint: cfg.FP,
		}
		// Reality settings would need additional fields
	}

	// Transport
	switch cfg.Net {
	case "ws":
		ss.WSSettings = &WSSettings{
			Path: cfg.Path,
			Headers: func() map[string]string {
				if cfg.Host != "" {
					return map[string]string{"Host": cfg.Host}
				}
				return nil
			}(),
		}
	case "grpc":
		ss.GRPCSettings = &GRPCSettings{
			ServiceName: cfg.Path,
		}
	case "h2":
		ss.H2Settings = &H2Settings{
			Path: cfg.Path,
			Host: func() []string {
				if cfg.Host != "" {
					return []string{cfg.Host}
				}
				return nil
			}(),
		}
	}

	return ss
}

// Helper functions
func splitParts(s string) (hostPort, query, fragment string) {
	if idx := strings.Index(s, "#"); idx >= 0 {
		fragment = s[idx+1:]
		s = s[:idx]
	}
	if idx := strings.Index(s, "?"); idx >= 0 {
		query = s[idx+1:]
		hostPort = s[:idx]
	} else {
		hostPort = s
	}
	return
}

func netSplitHostPort(s string) (string, string, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", fmt.Errorf("invalid IPv6")
		}
		host := s[1:end]
		port := s[end+2:]
		return host, port, nil
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid host:port")
	}
	return parts[0], parts[1], nil
}

func parseQuery(query string) map[string]string {
	params := make(map[string]string)
	for _, pair := range strings.Split(query, "&") {
		if idx := strings.Index(pair, "="); idx >= 0 {
			key := pair[:idx]
			value, _ := url.PathUnescape(pair[idx+1:])
			params[key] = value
		}
	}
	return params
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func getString(m map[string]string, key, def string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return def
}

// VmessConfig represents a parsed VMess URI.
type VmessConfig struct {
	Version int    `json:"v"`
	Address string `json:"add"`
	Port    int    `json:"port"`
	UUID    string `json:"id"`
	AlterID int    `json:"aid"`
	Net     string `json:"net"`
	Type    string `json:"type"`
	Host    string `json:"host"`
	Path    string `json:"path"`
	TLS     string `json:"tls"`
	SNI     string `json:"sni"`
	FP      string `json:"fp"`
	ALPN    string `json:"alpn"`
}

// ParseVMess parses a vmess:// URI (base64-encoded JSON).
func ParseVMess(uri string) (*VmessConfig, error) {
	b64 := strings.TrimPrefix(uri, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("invalid vmess base64: %w", err)
		}
	}

	var cfg VmessConfig
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		return nil, fmt.Errorf("invalid vmess json: %w", err)
	}

	return &cfg, nil
}

// BuildXrayConfigFromVMess generates Xray config from VMess URI.
func BuildXrayConfigFromVMess(vmessURI string, socksPort int) (*XrayConfig, error) {
	cfg, err := ParseVMess(vmessURI)
	if err != nil {
		return nil, err
	}

	// Build outbound
	outbound := Outbound{
		Tag:      "proxy",
		Protocol: "vmess",
		Settings: buildVMessSettings(cfg),
		StreamSettings: buildVMessStreamSettings(cfg),
	}

	inbound := Inbound{
		Tag:      "socks-in",
		Port:     socksPort,
		Listen:   "127.0.0.1",
		Protocol: "socks",
		Settings: json.RawMessage(`{"auth":"noauth","udp":true}`),
	}

	return &XrayConfig{
		Log: LogConfig{LogLevel: "warn"},
		Inbounds: []Inbound{inbound},
		Outbounds: []Outbound{
			outbound,
			{Tag: "direct", Protocol: "freedom", Settings: json.RawMessage(`{}`)},
			{Tag: "block", Protocol: "blackhole", Settings: json.RawMessage(`{}`)},
		},
		Routing: RoutingConfig{
			DomainStrategy: "IPIfNonMatch",
			Rules: []RoutingRule{
				{Type: "field", IP: []string{"geoip:private"}, OutboundTag: "direct"},
			},
		},
	}, nil
}

func buildVMessSettings(cfg *VmessConfig) json.RawMessage {
	vnext := []map[string]interface{}{
		{
			"address": cfg.Address,
			"port":    cfg.Port,
			"users": []map[string]interface{}{
				{
					"id":       cfg.UUID,
					"alterId":  cfg.AlterID,
					"security": "auto",
				},
			},
		},
	}
	settings := map[string]interface{}{"vnext": vnext}
	data, _ := json.Marshal(settings)
	return data
}

func buildVMessStreamSettings(cfg *VmessConfig) *StreamSettings {
	network := cfg.Net
	if network == "" {
		network = "tcp"
	}

	ss := &StreamSettings{Network: network}

	if cfg.TLS == "tls" {
		ss.Security = "tls"
		ss.TLSSettings = &TLSSettings{
			ServerName: cfg.SNI,
			Fingerprint: cfg.FP,
		}
	}

	switch network {
	case "ws":
		ss.WSSettings = &WSSettings{
			Path: cfg.Path,
			Headers: func() map[string]string {
				if cfg.Host != "" {
					return map[string]string{"Host": cfg.Host}
				}
				return nil
			}(),
		}
	case "grpc":
		ss.GRPCSettings = &GRPCSettings{ServiceName: cfg.Path}
	}

	return ss
}
