package sub

// CandyConnectProtocol represents a supported protocol ID from CandyConnect.
type CandyConnectProtocol string

const (
	ProtoV2Ray       CandyConnectProtocol = "v2ray"
	ProtoWireGuard   CandyConnectProtocol = "wireguard"
	ProtoOpenVPN     CandyConnectProtocol = "openvpn"
	ProtoIKEv2       CandyConnectProtocol = "ikev2"
	ProtoL2TP        CandyConnectProtocol = "l2tp"
	ProtoDNSTT       CandyConnectProtocol = "dnstt"
	ProtoSlipStream  CandyConnectProtocol = "slipstream"
	ProtoTrustTunnel CandyConnectProtocol = "trusttunnel"
)

// CandyConnectPreset is a fully-specified protocol configuration preset.
type CandyConnectPreset struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Protocol    CandyConnectProtocol `json:"protocol"`
	Description string               `json:"description"`
	DefaultPort int                  `json:"default_port"`
	Tags        []string             `json:"tags"`
	// Protocol-specific parameters
	Params map[string]interface{} `json:"params"`
}

// CandyConnectPresets returns the curated set of protocol presets.
func CandyConnectPresets() []CandyConnectPreset {
	return []CandyConnectPreset{
		{
			ID:          "candyconnect-v2ray-vmess",
			Name:        "V2Ray VMess",
			Protocol:    ProtoV2Ray,
			Description: "V2Ray VMess protocol - flexible proxy with strong obfuscation",
			DefaultPort: 10085,
			Tags:        []string{"v2ray", "vmess", "obfuscation"},
			Params: map[string]interface{}{
				"protocol": "vmess",
				"network":  "tcp",
			},
		},
		{
			ID:          "candyconnect-v2ray-vless-ws",
			Name:        "V2Ray VLESS+WebSocket",
			Protocol:    ProtoV2Ray,
			Description: "V2Ray VLESS over WebSocket for CDN traversal",
			DefaultPort: 10086,
			Tags:        []string{"v2ray", "vless", "websocket", "cdn"},
			Params: map[string]interface{}{
				"protocol": "vless",
				"network":  "ws",
			},
		},
		{
			ID:          "candyconnect-wireguard-default",
			Name:        "WireGuard Standard",
			Protocol:    ProtoWireGuard,
			Description: "WireGuard modern VPN - fast, minimal, cryptographically strong",
			DefaultPort: 51820,
			Tags:        []string{"wireguard", "udp", "kernel"},
			Params: map[string]interface{}{
				"mtu":       1420,
				"keepalive": 25,
			},
		},
		{
			ID:          "candyconnect-openvpn-tcp",
			Name:        "OpenVPN TCP",
			Protocol:    ProtoOpenVPN,
			Description: "OpenVPN over TCP - firewall-friendly, reliable",
			DefaultPort: 443,
			Tags:        []string{"openvpn", "tcp", "legacy"},
			Params: map[string]interface{}{
				"proto": "tcp",
				"port":  443,
			},
		},
		{
			ID:          "candyconnect-openvpn-udp",
			Name:        "OpenVPN UDP",
			Protocol:    ProtoOpenVPN,
			Description: "OpenVPN over UDP - better performance",
			DefaultPort: 1194,
			Tags:        []string{"openvpn", "udp", "legacy"},
			Params: map[string]interface{}{
				"proto": "udp",
				"port":  1194,
			},
		},
		{
			ID:          "candyconnect-ikev2",
			Name:        "IKEv2/IPSec",
			Protocol:    ProtoIKEv2,
			Description: "IKEv2/IPSec - native iOS/macOS/Windows support, mobile-friendly",
			DefaultPort: 500,
			Tags:        []string{"ikev2", "ipsec", "mobile", "native"},
			Params: map[string]interface{}{
				"port":   500,
				"udp":    4500,
				"cipher": "AES-256-GCM",
			},
		},
		{
			ID:          "candyconnect-l2tp",
			Name:        "L2TP/IPSec",
			Protocol:    ProtoL2TP,
			Description: "L2TP/IPSec legacy protocol - wide device support",
			DefaultPort: 1701,
			Tags:        []string{"l2tp", "ipsec", "legacy"},
			Params: map[string]interface{}{
				"port": 1701,
			},
		},
		{
			ID:          "candyconnect-dnstt",
			Name:        "DNSTT (DNS Tunnel)",
			Protocol:    ProtoDNSTT,
			Description: "DNS tunneling over TLS/DoT - censorship-resistant through DNS",
			DefaultPort: 853,
			Tags:        []string{"dns", "tunnel", "censorship-resistant", "dot"},
			Params: map[string]interface{}{
				"port":     853,
				"doh":      true,
				"resolver": "cloudflare-dns.com",
			},
		},
	}
}
