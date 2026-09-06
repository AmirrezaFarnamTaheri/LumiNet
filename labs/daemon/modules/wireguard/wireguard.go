// Package wireguard provides WireGuard configuration generation and IP management.
// Ported from algo VPN (Trail of Bits).
package wireguard

import (
	"fmt"
	"net"
)

// Default network ranges for WireGuard.
const (
	DefaultNetworkIPv4 = "10.49.0.0/16"
	DefaultNetworkIPv6 = "2001:db8:a160::/48"
	DefaultPort        = 51820
	DefaultMTU         = 1420
	KeepAliveSeconds   = 25
)

// Config holds WireGuard server/client configuration parameters.
type Config struct {
	ServerPrivateKey string
	ServerPublicKey  string
	ServerIP         string
	ListenPort       int
	NetworkIPv4      *net.IPNet
	NetworkIPv6      *net.IPNet
	DNSServers       []string
	MTU              int
}

// PeerConfig holds a WireGuard peer (client) configuration.
type PeerConfig struct {
	PrivateKey    string
	PublicKey     string
	PresharedKey  string
	IPAddress     string
	IPv6Address   string
	Endpoint      string
	AllowedIPs    []string
	KeepAlive     int
}

// GenerateServerConfig generates a WireGuard server configuration file.
// Ported from algo's roles/wireguard/templates/server.conf.j2
func (c *Config) GenerateServerConfig(peers []PeerConfig) string {
	var cfg string

	cfg += "[Interface]\n"
	cfg += fmt.Sprintf("Address = %s\n", c.ServerIP)
	cfg += fmt.Sprintf("ListenPort = %d\n", c.ListenPort)
	cfg += fmt.Sprintf("PrivateKey = %s\n", c.ServerPrivateKey)
	cfg += "SaveConfig = false\n"
	cfg += "\n"

	for _, peer := range peers {
		cfg += fmt.Sprintf("# %s\n", peer.IPAddress)
		cfg += "[Peer]\n"
		cfg += fmt.Sprintf("PublicKey = %s\n", peer.PublicKey)
		if peer.PresharedKey != "" {
			cfg += fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey)
		}
		cfg += fmt.Sprintf("AllowedIPs = %s/32\n", peer.IPAddress)
		if peer.IPv6Address != "" {
			cfg = cfg[:len(cfg)-1] // remove newline
			cfg += fmt.Sprintf(",%s/128\n", peer.IPv6Address)
		}
		cfg += "\n"
	}

	return cfg
}

// GenerateClientConfig generates a WireGuard client configuration file.
// Ported from algo's roles/wireguard/templates/client.conf.j2
func (c *Config) GenerateClientConfig(peer PeerConfig) string {
	var cfg string

	cfg += "[Interface]\n"
	cfg += fmt.Sprintf("PrivateKey = %s\n", peer.PrivateKey)
	cfg += fmt.Sprintf("Address = %s/32\n", peer.IPAddress)
	if peer.IPv6Address != "" {
		cfg += fmt.Sprintf("Address = %s/128\n", peer.IPv6Address)
	}
	if len(c.DNSServers) > 0 {
		for _, dns := range c.DNSServers {
			cfg += fmt.Sprintf("DNS = %s\n", dns)
		}
	}
	if c.MTU > 0 {
		cfg += fmt.Sprintf("MTU = %d\n", c.MTU)
	}
	cfg += "\n"

	cfg += "[Peer]\n"
	cfg += fmt.Sprintf("PublicKey = %s\n", c.ServerPublicKey)
	if peer.PresharedKey != "" {
		cfg += fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey)
	}
	cfg += fmt.Sprintf("Endpoint = %s\n", peer.Endpoint)

	if len(peer.AllowedIPs) > 0 {
		var ipsStr string
		for i, ip := range peer.AllowedIPs {
			if i > 0 {
				ipsStr += ", "
			}
			ipsStr += ip
		}
		cfg += fmt.Sprintf("AllowedIPs = %s\n", ipsStr)
	} else {
		cfg += "AllowedIPs = 0.0.0.0/0, ::/0\n"
	}

	if peer.KeepAlive > 0 {
		cfg += fmt.Sprintf("PersistentKeepalive = %d\n", peer.KeepAlive)
	}

	return cfg
}

// ExcludeSubnetsIPv4 returns AllowedIPs ranges excluding specific private subnets.
func ExcludeSubnetsIPv4(excludes []string) []string {
	has9 := false
	has10 := false
	for _, ex := range excludes {
		if ex == "9.0.0.0/8" {
			has9 = true
		}
		if ex == "10.0.0.0/8" {
			has10 = true
		}
	}
	if has9 && has10 {
		return []string{
			"0.0.0.0/5",
			"8.0.0.0/8",
			"11.0.0.0/8",
			"12.0.0.0/6",
			"16.0.0.0/4",
			"32.0.0.0/3",
			"64.0.0.0/2",
			"128.0.0.0/1",
		}
	}
	return []string{"0.0.0.0/0", "::/0"}
}

// IPManager manages IP address allocation for WireGuard peers.
type IPManager struct {
	networkIPv4 *net.IPNet
	networkIPv6 *net.IPNet
	nextIndex   int
	allocated   map[string]bool
}

// NewIPManager creates a new IP manager for the given network.
func NewIPManager(networkIPv4, networkIPv6 string) (*IPManager, error) {
	_, v4, err := net.ParseCIDR(networkIPv4)
	if err != nil {
		return nil, fmt.Errorf("invalid IPv4 network: %w", err)
	}

	var v6 *net.IPNet
	if networkIPv6 != "" {
		_, v6, err = net.ParseCIDR(networkIPv6)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv6 network: %w", err)
		}
	}

	return &IPManager{
		networkIPv4: v4,
		networkIPv6: v6,
		nextIndex:   0,
		allocated:   make(map[string]bool),
	}, nil
}

// AllocateServerIP returns the first usable IP in the network (for the server).
func (m *IPManager) AllocateServerIP() (string, string) {
	base := m.networkIPv4.IP.Mask(m.networkIPv4.Mask)
	serverIP := cloneIP(base)
	inc(serverIP)
	ipStr := serverIP.String()
	m.allocated[ipStr] = true

	var ipv6Str string
	if m.networkIPv6 != nil {
		baseV6 := m.networkIPv6.IP.Mask(m.networkIPv6.Mask)
		serverIPv6 := cloneIP(baseV6)
		inc(serverIPv6)
		ipv6Str = serverIPv6.String()
		m.allocated[ipv6Str] = true
	}

	return ipStr, ipv6Str
}

// AllocatePeerIP returns the next available IP for a peer.
// Server IP is at index+1, peers start at index+2.
func (m *IPManager) AllocatePeerIP() (string, string) {
	m.nextIndex++
	offset := m.nextIndex + 1 // +1 for server, +1 for peer offset

	base := m.networkIPv4.IP.Mask(m.networkIPv4.Mask)
	peerIP := cloneIP(base)
	for i := 0; i < offset; i++ {
		inc(peerIP)
	}
	ipStr := peerIP.String()
	m.allocated[ipStr] = true

	var ipv6Str string
	if m.networkIPv6 != nil {
		baseV6 := m.networkIPv6.IP.Mask(m.networkIPv6.Mask)
		peerIPv6 := cloneIP(baseV6)
		for i := 0; i < offset; i++ {
			inc(peerIPv6)
		}
		ipv6Str = peerIPv6.String()
		m.allocated[ipv6Str] = true
	}

	return ipStr, ipv6Str
}

// FormatEndpoint formats an endpoint with proper IPv6 bracket notation.
func FormatEndpoint(host string, port int) string {
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() == nil {
		// IPv6: use bracket notation
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// Helper functions
func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
