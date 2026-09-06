// Package sub provides Clash configuration utilities.
// (formerly package clashconfig) Clash/Mihomo configuration generation.
//
// Generates complete Clash YAML configs with:
// - Mixed inbound (SOCKS + HTTP)
// - DNS with fake-ip
// - Proxy groups (selector, urltest, fallback, load-balance)
// - Rule-based routing (DOMAIN, IP-CIDR, GEOSITE, GEOIP)
// - TUN config for system-wide proxy
package sub

import (
	"fmt"
	"strings"
)

// ClashConfig represents a complete Clash configuration.
type ClashConfig struct {
	MixedPort          int          `yaml:"mixed-port"`
	AllowLan           bool         `yaml:"allow-lan"`
	BindAddress        string       `yaml:"bind-address,omitempty"`
	Mode               string       `yaml:"mode"`
	LogLevel           string       `yaml:"log-level"`
	ExternalController string       `yaml:"external-controller,omitempty"`
	DNS                DNSConfig    `yaml:"dns"`
	Tun                TunConfig    `yaml:"tun,omitempty"`
	Proxies            []Proxy      `yaml:"proxies,omitempty"`
	ProxyGroups        []ProxyGroup `yaml:"proxy-groups,omitempty"`
	Rules              []string     `yaml:"rules"`
}

// DNSConfig holds DNS configuration.
type DNSConfig struct {
	Enable           bool              `yaml:"enable"`
	Listen           string            `yaml:"listen,omitempty"`
	EnhancedMode     string            `yaml:"enhanced-mode"`
	FakeIPRange      string            `yaml:"fake-ip-range,omitempty"`
	FakeIPFilter     []string          `yaml:"fake-ip-filter,omitempty"`
	Nameserver       []string          `yaml:"nameserver"`
	Fallback         []string          `yaml:"fallback,omitempty"`
	FallbackFilter   *FallbackFilter   `yaml:"fallback-filter,omitempty"`
	NameserverPolicy map[string]string `yaml:"nameserver-policy,omitempty"`
}

// FallbackFilter filters fallback DNS responses.
type FallbackFilter struct {
	GeoIP  bool     `yaml:"geoip"`
	IPCIDR []string `yaml:"ipcidr,omitempty"`
	Domain []string `yaml:"domain,omitempty"`
}

// TunConfig holds TUN device configuration.
type TunConfig struct {
	Enable              bool     `yaml:"enable"`
	Stack               string   `yaml:"stack"`
	DNSHijack           []string `yaml:"dns-hijack,omitempty"`
	AutoRoute           bool     `yaml:"auto-route"`
	AutoDetectInterface bool     `yaml:"auto-detect-interface"`
}

// Proxy represents a proxy server.
type Proxy struct {
	Name     string  `yaml:"name"`
	Type     string  `yaml:"type"`
	Server   string  `yaml:"server"`
	Port     int     `yaml:"port"`
	Password string  `yaml:"password,omitempty"`
	UUID     string  `yaml:"uuid,omitempty"`
	Network  string  `yaml:"network,omitempty"`
	TLS      bool    `yaml:"tls,omitempty"`
	SNI      string  `yaml:"sni,omitempty"`
	WSPath   string  `yaml:"ws-path,omitempty"`
	WSOpts   *WSOpts `yaml:"ws-opts,omitempty"`
	Cipher   string  `yaml:"cipher,omitempty"`
	UDP      bool    `yaml:"udp,omitempty"`
}

// WSOpts holds WebSocket options.
type WSOpts struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

// ProxyGroup represents a proxy group.
type ProxyGroup struct {
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`
	Proxies   []string `yaml:"proxies"`
	URL       string   `yaml:"url,omitempty"`
	Interval  int      `yaml:"interval,omitempty"`
	Tolerance int      `yaml:"tolerance,omitempty"`
}

// DefaultClashConfig returns a default Clash configuration.
func DefaultClashConfig() ClashConfig {
	return ClashConfig{
		MixedPort:          7890,
		AllowLan:           false,
		BindAddress:        "*",
		Mode:               "rule",
		LogLevel:           "info",
		ExternalController: "127.0.0.1:9090",
		DNS: DNSConfig{
			Enable:       true,
			Listen:       "0.0.0.0:53",
			EnhancedMode: "fake-ip",
			FakeIPRange:  "198.18.0.1/16",
			FakeIPFilter: []string{
				"*.lan", "*.local", "*.localhost",
				"localhost.ptlogin2.qq.com",
				"dns.msftncsi.com",
				"www.msftncsi.com",
				"www.msftconnecttest.com",
			},
			Nameserver: []string{
				"https://dns.alidns.com/dns-query",
				"https://doh.pub/dns-query",
			},
			Fallback: []string{
				"https://1.1.1.1/dns-query",
				"https://dns.google/dns-query",
			},
			FallbackFilter: &FallbackFilter{
				GeoIP:  true,
				IPCIDR: []string{"240.0.0.0/4", "0.0.0.0/32"},
			},
			NameserverPolicy: map[string]string{
				"geosite:cn": "https://dns.alidns.com/dns-query",
			},
		},
		Tun: TunConfig{
			Enable:              false,
			Stack:               "mixed",
			DNSHijack:           []string{"any:53"},
			AutoRoute:           true,
			AutoDetectInterface: true,
		},
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,Proxy",
			"DOMAIN-SUFFIX,github.com,Proxy",
			"DOMAIN-KEYWORD,google,Proxy",
			"GEOIP,CN,DIRECT",
			"GEOSITE,cn,DIRECT",
			"MATCH,Proxy",
		},
	}
}

// BuildClashYAML generates a Clash YAML config string.
func BuildClashYAML(config ClashConfig) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("mixed-port: %d\n", config.MixedPort))
	sb.WriteString(fmt.Sprintf("allow-lan: %v\n", config.AllowLan))
	sb.WriteString(fmt.Sprintf("bind-address: '%s'\n", config.BindAddress))
	sb.WriteString(fmt.Sprintf("mode: %s\n", config.Mode))
	sb.WriteString(fmt.Sprintf("log-level: %s\n", config.LogLevel))
	if config.ExternalController != "" {
		sb.WriteString(fmt.Sprintf("external-controller: %s\n", config.ExternalController))
	}

	// DNS
	sb.WriteString("dns:\n")
	sb.WriteString(fmt.Sprintf("  enable: %v\n", config.DNS.Enable))
	sb.WriteString(fmt.Sprintf("  listen: %s\n", config.DNS.Listen))
	sb.WriteString(fmt.Sprintf("  enhanced-mode: %s\n", config.DNS.EnhancedMode))
	sb.WriteString(fmt.Sprintf("  fake-ip-range: %s\n", config.DNS.FakeIPRange))
	sb.WriteString("  fake-ip-filter:\n")
	for _, f := range config.DNS.FakeIPFilter {
		sb.WriteString(fmt.Sprintf("    - '%s'\n", f))
	}
	sb.WriteString("  nameserver:\n")
	for _, ns := range config.DNS.Nameserver {
		sb.WriteString(fmt.Sprintf("    - %s\n", ns))
	}
	if len(config.DNS.Fallback) > 0 {
		sb.WriteString("  fallback:\n")
		for _, fb := range config.DNS.Fallback {
			sb.WriteString(fmt.Sprintf("    - %s\n", fb))
		}
	}

	// TUN
	if config.Tun.Enable {
		sb.WriteString("tun:\n")
		sb.WriteString(fmt.Sprintf("  enable: %v\n", config.Tun.Enable))
		sb.WriteString(fmt.Sprintf("  stack: %s\n", config.Tun.Stack))
		sb.WriteString("  dns-hijack:\n")
		for _, d := range config.Tun.DNSHijack {
			sb.WriteString(fmt.Sprintf("    - %s\n", d))
		}
		sb.WriteString(fmt.Sprintf("  auto-route: %v\n", config.Tun.AutoRoute))
		sb.WriteString(fmt.Sprintf("  auto-detect-interface: %v\n", config.Tun.AutoDetectInterface))
	}

	// Proxies
	if len(config.Proxies) > 0 {
		sb.WriteString("proxies:\n")
		for _, p := range config.Proxies {
			sb.WriteString(fmt.Sprintf("  - name: '%s'\n", p.Name))
			sb.WriteString(fmt.Sprintf("    type: %s\n", p.Type))
			sb.WriteString(fmt.Sprintf("    server: %s\n", p.Server))
			sb.WriteString(fmt.Sprintf("    port: %d\n", p.Port))
			if p.Password != "" {
				sb.WriteString(fmt.Sprintf("    password: '%s'\n", p.Password))
			}
			if p.UUID != "" {
				sb.WriteString(fmt.Sprintf("    uuid: %s\n", p.UUID))
			}
			if p.Network != "" {
				sb.WriteString(fmt.Sprintf("    network: %s\n", p.Network))
			}
			if p.TLS {
				sb.WriteString("    tls: true\n")
			}
			if p.SNI != "" {
				sb.WriteString(fmt.Sprintf("    servername: %s\n", p.SNI))
			}
			if p.WSPath != "" {
				sb.WriteString(fmt.Sprintf("    ws-path: %s\n", p.WSPath))
			}
			if p.Cipher != "" {
				sb.WriteString(fmt.Sprintf("    cipher: %s\n", p.Cipher))
			}
			if p.UDP {
				sb.WriteString("    udp: true\n")
			}
		}
	}

	// Proxy Groups
	if len(config.ProxyGroups) > 0 {
		sb.WriteString("proxy-groups:\n")
		for _, g := range config.ProxyGroups {
			sb.WriteString(fmt.Sprintf("  - name: '%s'\n", g.Name))
			sb.WriteString(fmt.Sprintf("    type: %s\n", g.Type))
			sb.WriteString("    proxies:\n")
			for _, p := range g.Proxies {
				sb.WriteString(fmt.Sprintf("      - '%s'\n", p))
			}
			if g.URL != "" {
				sb.WriteString(fmt.Sprintf("    url: %s\n", g.URL))
			}
			if g.Interval > 0 {
				sb.WriteString(fmt.Sprintf("    interval: %d\n", g.Interval))
			}
		}
	}

	// Rules
	sb.WriteString("rules:\n")
	for _, r := range config.Rules {
		sb.WriteString(fmt.Sprintf("  - %s\n", r))
	}

	return sb.String()
}

// GenerateDefaultProxyGroup creates a standard proxy group structure.
func GenerateDefaultProxyGroup(proxyNames []string) []ProxyGroup {
	allProxies := append([]string{"DIRECT", "REJECT"}, proxyNames...)

	return []ProxyGroup{
		{
			Name:    "Proxy",
			Type:    "select",
			Proxies: append([]string{"Auto"}, allProxies...),
		},
		{
			Name:      "Auto",
			Type:      "url-test",
			Proxies:   proxyNames,
			URL:       "https://www.gstatic.com/generate_204",
			Interval:  300,
			Tolerance: 50,
		},
	}
}
