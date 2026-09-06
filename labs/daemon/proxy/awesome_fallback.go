package proxy

// AwesomeFallbackConfig maps known blocked proxy types to recommended fallback protocols.
// Ported from awesome-anti-censorship recommendations.
type AwesomeFallbackConfig struct {
	FallbackMap map[string]string
}

// DefaultAwesomeFallback returns standard fallback mappings for bypassing DPI.
func DefaultAwesomeFallback() *AwesomeFallbackConfig {
	return &AwesomeFallbackConfig{
		FallbackMap: map[string]string{
			"http":        "trojan",
			"socks5":      "vless",
			"shadowsocks": "xray-vless-xtls",
			"openvpn":     "wireguard-obfs",
			"wireguard":   "amnezia-wg",
		},
	}
}

// GetFallback returns the recommended fallback protocol for a given blocked protocol.
func (c *AwesomeFallbackConfig) GetFallback(protocol string) string {
	if fb, ok := c.FallbackMap[protocol]; ok {
		return fb
	}
	return "vless" // Default fallback
}
