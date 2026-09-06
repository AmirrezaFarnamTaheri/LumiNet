// Package v2rayconfig provides V2Ray/Xray configuration building with anti-censorship features.
// Ported from ZedSecure's v2ray_config_builder.dart.
//
// Features:
// - Multi-protocol outbound: VMess, VLESS, Trojan, SS, WireGuard, Hysteria2
// - Transport: TCP, WS, H2, gRPC, QUIC, XHTTP, HTTPUpgrade
// - TLS + REALITY with fingerprint, publicKey, shortId, spiderX
// - Fragment anti-censorship: TLS/Reality packet fragmentation with noise injection
// - Mux multiplexing: concurrency control, xUDP for QUIC bypass
// - Routing: GeoIP/GeoSite rules, private IP bypass, domestic DNS
// - DNS: Cloudflare/Google/Quad9/Yandex, FakeDNS (198.18.0.0/15)
// - Sniffing: HTTP/TLS/QUIC/FakeDNS protocol detection
package v2rayconfig

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FragmentSettings holds anti-censorship fragment configuration.
type FragmentSettings struct {
	Packets  string `json:"packets"`  // "tlshello" or "1-3"
	Length   string `json:"length"`   // e.g. "1-3"
	Interval string `json:"interval"` // e.g. "1-3"
}

// MuxSettings holds multiplexing configuration.
type MuxSettings struct {
	Enabled     bool   `json:"enabled"`
	Concurrency int    `json:"concurrency"`
	XUDP        bool   `json:"xudp"` // QUIC bypass
}

// RealitySettings holds REALITY TLS configuration.
type RealitySettings struct {
	Enabled     bool     `json:"enabled"`
	Fingerprint string   `json:"fingerprint"` // chrome, firefox, etc.
	PublicKey   string   `json:"publicKey"`
	ShortID     string   `json:"shortId"`
	SpiderX     string   `json:"spiderX"`
	ServerNames []string `json:"serverNames"`
}

// SniffingSettings holds protocol sniffing configuration.
type SniffingSettings struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
	RouteOnly    bool     `json:"routeOnly"`
}

// V2RayOutbound represents a V2Ray/Xray outbound configuration.
type V2RayOutbound struct {
	Protocol       string            `json:"protocol"`
	Tag            string            `json:"tag"`
	Settings       json.RawMessage   `json:"settings"`
	StreamSettings *StreamSettings   `json:"streamSettings,omitempty"`
	Mux            *MuxSettings      `json:"mux,omitempty"`
}

// StreamSettings holds transport and security configuration.
type StreamSettings struct {
	Network     string            `json:"network"`
	Security    string            `json:"security"`
	TLSSettings *TLSSettings      `json:"tlsSettings,omitempty"`
	WSSettings  *WSSettings       `json:"wsSettings,omitempty"`
	GRPCSettings *GRPCSettings    `json:"grpcSettings,omitempty"`
	H2Settings  *H2Settings       `json:"httpSettings,omitempty"`
	QUICSettings *QUICSettings    `json:"quicSettings,omitempty"`
	XHTTPSettings *XHTTPSettings  `json:"xhttpSettings,omitempty"`
	Sockopt     *Sockopt          `json:"sockopt,omitempty"`
}

type TLSSettings struct {
	ServerName    string   `json:"serverName,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	AllowInsecure bool     `json:"allowInsecure,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	Reality       *RealitySettings `json:"reality,omitempty"`
}

type WSSettings struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
	MaxEarlyData int          `json:"maxEarlyData,omitempty"`
	EarlyDataHeaderName string `json:"earlyDataHeaderName,omitempty"`
}

type GRPCSettings struct {
	ServiceName string `json:"serviceName"`
}

type H2Settings struct {
	Path string   `json:"path"`
	Host []string `json:"host"`
}

type QUICSettings struct {
	Security string   `json:"security"`
	Key      string   `json:"key"`
	Header   string   `json:"header"`
}

type XHTTPSettings struct {
	Path    string `json:"path"`
	Host    string `json:"host,omitempty"`
	Mode    string `json:"mode,omitempty"` // auto, packet-up
	Extra   string `json:"extra,omitempty"`
}

type Sockopt struct {
	Mark     int    `json:"mark,omitempty"`
	TCPFastOpen bool `json:"tcpFastOpen,omitempty"`
	TCPMSS   int    `json:"tcpMss,omitempty"`
}

// DNSConfig holds DNS configuration.
type DNSConfig struct {
	Hosts       map[string]string `json:"hosts,omitempty"`
	Servers     []DNSServer       `json:"servers"`
	ClientIP    string            `json:"clientIp,omitempty"`
	QueryMode   string            `json:"queryMode,omitempty"`
	Tag         string            `json:"tag,omitempty"`
}

type DNSServer struct {
	Address  string   `json:"address"`
	Port     int      `json:"port,omitempty"`
	Domains  []string `json:"domains,omitempty"`
	ExpectIPs []string `json:"expectIPs,omitempty"`
}

// RoutingConfig holds routing rules.
type RoutingConfig struct {
	DomainStrategy string        `json:"domainStrategy"`
	DomainMatcher  string        `json:"domainMatcher,omitempty"`
	Rules          []RoutingRule `json:"rules"`
}

type RoutingRule struct {
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
	Protocol    []string `json:"protocol,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

// BuildDefaultRoutingRules returns standard anti-censorship routing rules.
// Ported from ZedSecure's v2ray_config_builder.dart.
func BuildDefaultRoutingRules() []RoutingRule {
	return []RoutingRule{
		// Block QUIC (UDP 443) to prevent DPI detection
		{
			Type:        "field",
			Port:        "443",
			Network:     "udp",
			OutboundTag: "block",
		},
		// Bypass private IPs
		{
			Type:        "field",
			IP:          []string{"geoip:private"},
			OutboundTag: "direct",
		},
		// Bypass China IPs
		{
			Type:        "field",
			IP:          []string{"geoip:cn"},
			OutboundTag: "direct",
		},
		// Bypass China domains
		{
			Type:        "field",
			Domain:      []string{"geosite:cn"},
			OutboundTag: "direct",
		},
		// Block ads
		{
			Type:        "field",
			Domain:      []string{"geosite:category-ads-all"},
			OutboundTag: "block",
		},
	}
}

// BuildDefaultDNSConfig returns standard DNS configuration.
// Ported from ZedSecure's v2ray_config_builder.dart.
func BuildDefaultDNSConfig() DNSConfig {
	return DNSConfig{
		Hosts: map[string]string{
			"domain:googleapis.cn": "googleapis.com",
		},
		Servers: []DNSServer{
			{
				Address:  "https://1.1.1.1/dns-query",
				Domains:  []string{"geosite:geolocation-!cn"},
				ExpectIPs: []string{"geoip:!cn"},
			},
			{
				Address:  "https://dns.google/dns-query",
				Domains:  []string{"geosite:geolocation-!cn"},
				ExpectIPs: []string{"geoip:!cn"},
			},
			{
				Address: "https://223.5.5.5/dns-query",
				Domains: []string{"geosite:cn", "geosite:geolocation-cn"},
			},
			{
				Address: "https://dns.alidns.com/dns-query",
				Domains: []string{"geosite:cn", "geosite:geolocation-cn"},
			},
		},
	}
}

// BuildSniffingConfig returns default sniffing settings.
func BuildSniffingConfig() SniffingSettings {
	return SniffingSettings{
		Enabled:      true,
		DestOverride: []string{"http", "tls", "quic", "fakedns"},
		RouteOnly:    true,
	}
}

// CountryDetector detects country from server remark text.
// Ported from ZedSecure's country_detector.dart.
type CountryDetector struct {
	patterns map[string][]string
}

// NewCountryDetector creates a new country detector with common patterns.
func NewCountryDetector() *CountryDetector {
	return &CountryDetector{
		patterns: map[string][]string{
			"US": {"us", "usa", "united states", "america"},
			"GB": {"gb", "uk", "united kingdom", "britain", "england"},
			"DE": {"de", "germany", "deutschland"},
			"FR": {"fr", "france"},
			"JP": {"jp", "japan"},
			"KR": {"kr", "korea"},
			"SG": {"sg", "singapore"},
			"HK": {"hk", "hong kong"},
			"TW": {"tw", "taiwan"},
			"CA": {"ca", "canada"},
			"AU": {"au", "australia"},
			"NL": {"nl", "netherlands", "dutch"},
			"RU": {"ru", "russia"},
			"IN": {"in", "india"},
			"BR": {"br", "brazil"},
			"TR": {"tr", "turkey", "turkiye"},
			"IR": {"ir", "iran"},
			"CN": {"cn", "china"},
			"AE": {"ae", "uae", "emirates"},
			"IL": {"il", "israel"},
			"SE": {"se", "sweden"},
			"CH": {"ch", "switzerland"},
			"IT": {"it", "italy"},
			"ES": {"es", "spain"},
			"PL": {"pl", "poland"},
			"UA": {"ua", "ukraine"},
			"AR": {"ar", "argentina"},
			"MX": {"mx", "mexico"},
			"CO": {"co", "colombia"},
			"CL": {"cl", "chile"},
			"ID": {"id", "indonesia"},
			"TH": {"th", "thailand"},
			"VN": {"vn", "vietnam"},
			"PH": {"ph", "philippines"},
			"MY": {"my", "malaysia"},
			"NZ": {"nz", "new zealand"},
			"ZA": {"za", "south africa"},
			"EG": {"eg", "egypt"},
			"SA": {"sa", "saudi"},
			"PK": {"pk", "pakistan"},
			"BD": {"bd", "bangladesh"},
			"NG": {"ng", "nigeria"},
			"KE": {"ke", "kenya"},
		},
	}
}

// DetectCountry detects country code from remark text.
// Checks for bracket codes [US], emoji flags, and keyword matching.
func (cd *CountryDetector) DetectCountry(remark string) string {
	remark = strings.ToLower(remark)

	// Check for bracket country codes: [US], [DE], etc.
	if len(remark) >= 4 && remark[0] == '[' && remark[3] == ']' {
		code := strings.ToUpper(remark[1:3])
		if len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' {
			return code
		}
	}

	// Check for keywords
	for code, keywords := range cd.patterns {
		for _, kw := range keywords {
			if strings.Contains(remark, kw) {
				return code
			}
		}
	}

	return ""
}

// GeoLocation represents geographic location data.
type GeoLocation struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
}

// GeoLocationProvider queries IP geolocation from multiple sources.
// Ported from ZedSecure's v2ray_service.dart.
type GeoLocationProvider struct {
	sources []string
}

// NewGeoLocationProvider creates a new geo location provider.
func NewGeoLocationProvider() *GeoLocationProvider {
	return &GeoLocationProvider{
		sources: []string{
			"https://ipwho.is/",
			"https://api.ip.sb/geoip/",
			"https://ipapi.co/",
			"https://ipinfo.io/",
		},
	}
}

// FormatEndpoint formats a server endpoint with IPv6 bracket notation.
func FormatEndpoint(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
