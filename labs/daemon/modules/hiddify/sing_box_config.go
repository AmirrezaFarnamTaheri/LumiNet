package hiddify

import (
	"encoding/json"
	"fmt"
)

// LogConfig defines the logging configurations for sing-box.
type LogConfig struct {
	Disabled  bool   `json:"disabled,omitempty"`
	Level     string `json:"level,omitempty"`
	Output    string `json:"output,omitempty"`
	Timestamp bool   `json:"timestamp,omitempty"`
}

// DNSServerConfig defines a single DNS server configuration.
type DNSServerConfig struct {
	Tag             string   `json:"tag"`
	Address         string   `json:"address"`
	AddressResolver string   `json:"address_resolver,omitempty"`
	AddressSubnet   string   `json:"address_subnet,omitempty"`
	Strategy        string   `json:"strategy,omitempty"`
	Detour          string   `json:"detour,omitempty"`
	ClientSubnet    string   `json:"client_subnet,omitempty"`
}

// DNSRuleConfig defines a DNS routing rule.
type DNSRuleConfig struct {
	Inbound  []string `json:"inbound,omitempty"`
	Domain   []string `json:"domain,omitempty"`
	IP       []string `json:"ip,omitempty"`
	Server   string   `json:"server"`
	DisableCache bool `json:"disable_cache,omitempty"`
}

// DNSConfig defines the DNS resolution system settings.
type DNSConfig struct {
	Servers []DNSServerConfig `json:"servers"`
	Rules   []DNSRuleConfig   `json:"rules,omitempty"`
	Final   string            `json:"final"`
	Strategy string           `json:"strategy,omitempty"`
}

// InboundConfig defines inbound connections.
type InboundConfig struct {
	Type              string `json:"type"`
	Tag               string `json:"tag"`
	Listen            string `json:"listen,omitempty"`
	ListenPort        int    `json:"listen_port,omitempty"`
	Stack             string `json:"stack,omitempty"`
	InterfaceName     string `json:"interface_name,omitempty"`
	MTU               int    `json:"mtu,omitempty"`
	Inet4Address      string `json:"inet4_address,omitempty"`
	Inet6Address      string `json:"inet6_address,omitempty"`
	AutoRoute         bool   `json:"auto_route,omitempty"`
	StrictRoute       bool   `json:"strict_route,omitempty"`
	EndpointIPPacket  bool   `json:"endpoint_ip_packet,omitempty"`
}

// MultiplexConfig defines outbound stream multiplexing (Mux).
type MultiplexConfig struct {
	Enabled        bool   `json:"enabled"`
	Protocol       string `json:"protocol,omitempty"` // h2mux, smux
	MaxConnections int    `json:"max_connections,omitempty"`
	MinStreams     int    `json:"min_streams,omitempty"`
	MaxStreams     int    `json:"max_streams,omitempty"`
	Padding        bool   `json:"padding,omitempty"`
}

// TLSConfig defines transport layer security settings.
type TLSConfig struct {
	Enabled    bool     `json:"enabled"`
	ServerName string   `json:"server_name,omitempty"`
	Insecure   bool     `json:"insecure,omitempty"`
	Alpn       []string `json:"alpn,omitempty"`
	UTLS       *struct {
		Enabled     bool   `json:"enabled"`
		Fingerprint string `json:"fingerprint,omitempty"`
	} `json:"utls,omitempty"`
}

// TransportConfig defines transport layer wrapper protocols (WS, gRPC, xhttp, HTTPUpgrade).
type TransportConfig struct {
	Type        string                 `json:"type"`
	Host        string                 `json:"host,omitempty"`
	Path        string                 `json:"path,omitempty"`
	ServiceName string                 `json:"service_name,omitempty"`
	Headers     map[string]interface{} `json:"headers,omitempty"`
}

// AmneziaWGConfig defines obfuscated handshake header parameters for Amnezia WireGuard.
type AmneziaWGConfig struct {
	Jc   int `json:"jc,omitempty"`
	Jmin int `json:"jmin,omitempty"`
	Jmax int `json:"jmax,omitempty"`
	S1   int `json:"s1,omitempty"`
	S2   int `json:"s2,omitempty"`
}

// OutboundConfig defines outbound connection destinations.
type OutboundConfig struct {
	Type          string           `json:"type"`
	Tag           string           `json:"tag"`
	Server        string           `json:"server,omitempty"`
	ServerPort    int              `json:"server_port,omitempty"`
	Method        string           `json:"method,omitempty"`
	Password      string           `json:"password,omitempty"`
	UUID          string           `json:"uuid,omitempty"`
	Network       string           `json:"network,omitempty"`
	TLS           *TLSConfig       `json:"tls,omitempty"`
	Multiplex     *MultiplexConfig `json:"multiplex,omitempty"`
	Flow          string           `json:"flow,omitempty"`
	PacketEncoding string        `json:"packet_encoding,omitempty"`
	PrivateKey    string           `json:"private_key,omitempty"`
	PeerPublicKey string           `json:"peer_public_key,omitempty"`
	Reserved      []byte           `json:"reserved,omitempty"`
	LocalAddress  []string         `json:"local_address,omitempty"`
	MTU           int              `json:"mtu,omitempty"`
	Transport     *TransportConfig `json:"transport,omitempty"`
	Amnezia       *AmneziaWGConfig `json:"amnezia,omitempty"`
}

// RouteRuleConfig defines a traffic routing rule.
type RouteRuleConfig struct {
	Inbound  []string `json:"inbound,omitempty"`
	IP       []string `json:"ip,omitempty"`
	Domain   []string `json:"domain,omitempty"`
	Protocol []string `json:"protocol,omitempty"`
	Port     []int    `json:"port,omitempty"`
	Outbound string   `json:"outbound"`
}

// RouteConfig defines routing rules.
type RouteConfig struct {
	Rules               []RouteRuleConfig `json:"rules"`
	Final               string            `json:"final"`
	AutoDetectInterface bool              `json:"auto_detect_interface,omitempty"`
}

// ExperimentalConfig defines experimental features.
type ExperimentalConfig struct {
	ClashAPI *struct {
		ExternalController string `json:"external_controller"`
		ExternalUI         string `json:"external_ui,omitempty"`
	} `json:"clash_api,omitempty"`
}

// SingBoxConfig represents the complete configuration schema for sing-box.
type SingBoxConfig struct {
	Log          *LogConfig          `json:"log,omitempty"`
	DNS          *DNSConfig          `json:"dns,omitempty"`
	Inbounds     []InboundConfig     `json:"inbounds"`
	Outbounds    []OutboundConfig    `json:"outbounds"`
	Route        *RouteConfig        `json:"route,omitempty"`
	Experimental *ExperimentalConfig `json:"experimental,omitempty"`
}

// NewDefaultSingBoxConfig builds a base configuration template.
func NewDefaultSingBoxConfig() *SingBoxConfig {
	return &SingBoxConfig{
		Log: &LogConfig{
			Level:  "info",
			Output: "stdout",
		},
		DNS: &DNSConfig{
			Servers: []DNSServerConfig{
				{
					Tag:     "dns-direct",
					Address: "8.8.8.8",
					Detour:  "direct",
				},
			},
			Final: "dns-direct",
		},
		Inbounds: []InboundConfig{
			{
				Type:       "mixed",
				Tag:        "mixed-in",
				Listen:     "127.0.0.1",
				ListenPort: 2080,
			},
		},
		Outbounds: []OutboundConfig{
			{
				Type: "direct",
				Tag:  "direct",
			},
			{
				Type: "block",
				Tag:  "block",
			},
		},
		Route: &RouteConfig{
			Rules: []RouteRuleConfig{
				{
					Protocol: []string{"dns"},
					Outbound: "dns-out",
				},
			},
			Final:               "direct",
			AutoDetectInterface: true,
		},
	}
}

// BuildJSON serializes the config to a valid JSON string.
func (c *SingBoxConfig) BuildJSON() (string, error) {
	bytes, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize sing-box config: %w", err)
	}
	return string(bytes), nil
}

// AddWireguardOutbound constructs and adds a WireGuard outbound to the configuration,
// and appends a direct routing rule for the endpoint IP to prevent loops.
func (c *SingBoxConfig) AddWireguardOutbound(tag, endpoint string, port int, privateKey, peerPublicKey string, reserved []byte, localAddresses []string) {
	c.Outbounds = append(c.Outbounds, OutboundConfig{
		Type:          "wireguard",
		Tag:           tag,
		Server:        endpoint,
		ServerPort:    port,
		PrivateKey:    privateKey,
		PeerPublicKey: peerPublicKey,
		Reserved:      reserved,
		LocalAddress:  localAddresses,
	})

	// Add routing rule to bypass this endpoint IP directly
	if c.Route != nil {
		c.Route.Rules = append([]RouteRuleConfig{{
			IP:       []string{fmt.Sprintf("%s/32", endpoint)},
			Outbound: "direct",
		}}, c.Route.Rules...)
	}
}
