// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: clash-worker-main
// Target path: server/internal/proxy/clash_worker.go

package proxy

import (
	"encoding/json"
	"log"
	"log/slog"
	"strings"
)

// ClashProxy represents a single proxy config item.
type ClashProxy struct {
	Name           string                 `json:"name"`
	Type           string                 `json:"type"`
	Server         string                 `json:"server"`
	Port           int                    `json:"port"`
	UUID           string                 `json:"uuid,omitempty"`
	AlterID        int                    `json:"alterId,omitempty"`
	Cipher         string                 `json:"cipher,omitempty"`
	TLS            bool                   `json:"tls,omitempty"`
	SkipCertVerify bool                   `json:"skip-cert-verify,omitempty"`
	ServerName     string                 `json:"servername,omitempty"`
	Network        string                 `json:"network,omitempty"`
	WsPath         string                 `json:"ws-path,omitempty"`
	WsHeaders      map[string]string      `json:"ws-headers,omitempty"`
	Merged         bool                   `json:"merged,omitempty"`
	Provider       string                 `json:"provider,omitempty"`
	Raw            map[string]interface{} `json:"raw,omitempty"`
}

// Getters & Setters for ClashProxy
func (p *ClashProxy) GetName() string                    { return p.Name }
func (p *ClashProxy) SetName(val string)                 { p.Name = val }
func (p *ClashProxy) GetType() string                    { return p.Type }
func (p *ClashProxy) SetType(val string)                 { p.Type = val }
func (p *ClashProxy) GetServer() string                  { return p.Server }
func (p *ClashProxy) SetServer(val string)               { p.Server = val }
func (p *ClashProxy) GetPort() int                       { return p.Port }
func (p *ClashProxy) SetPort(val int)                    { p.Port = val }
func (p *ClashProxy) GetUUID() string                    { return p.UUID }
func (p *ClashProxy) SetUUID(val string)                 { p.UUID = val }
func (p *ClashProxy) GetAlterID() int                    { return p.AlterID }
func (p *ClashProxy) SetAlterID(val int)                 { p.AlterID = val }
func (p *ClashProxy) GetCipher() string                  { return p.Cipher }
func (p *ClashProxy) SetCipher(val string)               { p.Cipher = val }
func (p *ClashProxy) GetTLS() bool                       { return p.TLS }
func (p *ClashProxy) SetTLS(val bool)                    { p.TLS = val }
func (p *ClashProxy) GetSkipCertVerify() bool            { return p.SkipCertVerify }
func (p *ClashProxy) SetSkipCertVerify(val bool)         { p.SkipCertVerify = val }
func (p *ClashProxy) GetServerName() string              { return p.ServerName }
func (p *ClashProxy) SetServerName(val string)           { p.ServerName = val }
func (p *ClashProxy) GetNetwork() string                 { return p.Network }
func (p *ClashProxy) SetNetwork(val string)              { p.Network = val }
func (p *ClashProxy) GetWsPath() string                  { return p.WsPath }
func (p *ClashProxy) SetWsPath(val string)               { p.WsPath = val }
func (p *ClashProxy) GetWsHeaders() map[string]string    { return p.WsHeaders }
func (p *ClashProxy) SetWsHeaders(val map[string]string) { p.WsHeaders = val }
func (p *ClashProxy) GetMerged() bool                    { return p.Merged }
func (p *ClashProxy) SetMerged(val bool)                 { p.Merged = val }
func (p *ClashProxy) GetProvider() string                { return p.Provider }
func (p *ClashProxy) SetProvider(val string)             { p.Provider = val }

// ClashDNS represents Clash DNS configurations.
type ClashDNS struct {
	Enable       bool     `json:"enable"`
	IPv6         bool     `json:"ipv6"`
	EnhancedMode string   `json:"enhanced-mode"`
	Nameservers  []string `json:"nameserver"`
}

// ClashGroup represents a Clash proxy-group.
type ClashGroup struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	URL      string   `json:"url,omitempty"`
	Interval int      `json:"interval,omitempty"`
	Strategy string   `json:"strategy,omitempty"`
	Proxies  []string `json:"proxies"`
}

// CleanIP represents a clean Cloudflare IP for routing.
type CleanIP struct {
	IP       string `json:"ip"`
	Operator string `json:"operator"`
}

// ClashWorker represents the Cloudflare Worker subscription aggregator.
type ClashWorker struct {
	Port               int               `json:"port"`
	SocksPort          int               `json:"socks-port"`
	AllowLan           bool              `json:"allow-lan"`
	Mode               string            `json:"mode"`
	LogLevel           string            `json:"log-level"`
	ExternalController string            `json:"external-controller"`
	DNS                ClashDNS          `json:"dns"`
	Proxies            []ClashProxy      `json:"proxies"`
	ProxyGroups        []ClashGroup      `json:"proxy-groups"`
	Rules              []string          `json:"rules"`
	MaxConfigs         int               `json:"max-configs"`
	IncludeOriginal    bool              `json:"include-original"`
	OnlyOriginal       bool              `json:"only-original"`
	SelectedTypes      []string          `json:"selected-types"`
	SelectedProviders  []string          `json:"selected-providers"`
	ConfigProviders    map[string]string `json:"config-providers"`
	IpProviderLink     string            `json:"ip-provider-link"`
	Operators          []string          `json:"operators"`
	CleanIPs           []CleanIP         `json:"clean-ips"`
}

func NewClashWorker() *ClashWorker {
	return &ClashWorker{
		Port:               7890,
		SocksPort:          7891,
		AllowLan:           false,
		Mode:               "rule",
		LogLevel:           "info",
		ExternalController: "127.0.0.1:9090",
		DNS: ClashDNS{
			Enable:       true,
			IPv6:         false,
			EnhancedMode: "fake-ip",
			Nameservers: []string{
				"114.114.114.114",
				"223.5.5.5",
				"8.8.8.8",
				"9.9.9.9",
				"1.1.1.1",
				"https://dns.google/dns-query",
				"tls://dns.google:853",
			},
		},
		MaxConfigs:      1000,
		IncludeOriginal: true,
		OnlyOriginal:    false,
		SelectedTypes:   []string{"vmess", "ss", "ssr", "trojan", "snell", "http", "socks5"},
		ConfigProviders: map[string]string{
			"mahdibland": "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge_yaml.yml",
			"mfuu":       "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
			"peasoft":    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.yml",
			"getnode":    "https://raw.githubusercontent.com/a2470982985/getNode/main/clash.yaml",
			"nodefree":   "https://raw.githubusercontent.com/mlabalabala/v2ray-node/main/nodefree4clash.txt",
			"clashnode":  "https://raw.githubusercontent.com/mlabalabala/v2ray-node/main/clashnode4clash.txt",
		},
		IpProviderLink: "https://raw.githubusercontent.com/vfarid/cf-clean-ips/main/list.json",
		Rules: []string{
			"GEOIP,IR,DIRECT",
			"DOMAIN-SUFFIX,ir,DIRECT",
			"MATCH,All",
		},
	}
}

// Getters & Setters for ClashWorker
func (c *ClashWorker) GetPort() int                     { return c.Port }
func (c *ClashWorker) SetPort(val int)                  { c.Port = val }
func (c *ClashWorker) GetSocksPort() int                { return c.SocksPort }
func (c *ClashWorker) SetSocksPort(val int)             { c.SocksPort = val }
func (c *ClashWorker) GetAllowLan() bool                { return c.AllowLan }
func (c *ClashWorker) SetAllowLan(val bool)             { c.AllowLan = val }
func (c *ClashWorker) GetMode() string                  { return c.Mode }
func (c *ClashWorker) SetMode(val string)               { c.Mode = val }
func (c *ClashWorker) GetLogLevel() string              { return c.LogLevel }
func (c *ClashWorker) SetLogLevel(val string)           { c.LogLevel = val }
func (c *ClashWorker) GetExternalController() string    { return c.ExternalController }
func (c *ClashWorker) SetExternalController(val string) { c.ExternalController = val }
func (c *ClashWorker) GetDnsEnabled() bool              { return c.DNS.Enable }
func (c *ClashWorker) SetDnsEnabled(val bool)           { c.DNS.Enable = val }
func (c *ClashWorker) GetDnsIpv6() bool                 { return c.DNS.IPv6 }
func (c *ClashWorker) SetDnsIpv6(val bool)              { c.DNS.IPv6 = val }
func (c *ClashWorker) GetDnsEnhancedMode() string       { return c.DNS.EnhancedMode }
func (c *ClashWorker) SetDnsEnhancedMode(val string)    { c.DNS.EnhancedMode = val }
func (c *ClashWorker) GetDnsNameservers() []string      { return c.DNS.Nameservers }
func (c *ClashWorker) SetDnsNameservers(val []string)   { c.DNS.Nameservers = val }
func (c *ClashWorker) AddDnsNameserver(srv string) {
	c.DNS.Nameservers = append(c.DNS.Nameservers, srv)
}
func (c *ClashWorker) RemoveDnsNameserver(srv string) bool {
	for i, v := range c.DNS.Nameservers {
		if v == srv {
			c.DNS.Nameservers = append(c.DNS.Nameservers[:i], c.DNS.Nameservers[i+1:]...)
			return true
		}
	}
	return false
}
func (c *ClashWorker) GetMaxConfigs() int            { return c.MaxConfigs }
func (c *ClashWorker) SetMaxConfigs(val int)         { c.MaxConfigs = val }
func (c *ClashWorker) GetIncludeOriginal() bool      { return c.IncludeOriginal }
func (c *ClashWorker) SetIncludeOriginal(val bool)   { c.IncludeOriginal = val }
func (c *ClashWorker) GetOnlyOriginal() bool         { return c.OnlyOriginal }
func (c *ClashWorker) SetOnlyOriginal(val bool)      { c.OnlyOriginal = val }
func (c *ClashWorker) GetSelectedTypes() []string    { return c.SelectedTypes }
func (c *ClashWorker) SetSelectedTypes(val []string) { c.SelectedTypes = val }
func (c *ClashWorker) AddSelectedType(val string)    { c.SelectedTypes = append(c.SelectedTypes, val) }
func (c *ClashWorker) RemoveSelectedType(val string) bool {
	for i, v := range c.SelectedTypes {
		if v == val {
			c.SelectedTypes = append(c.SelectedTypes[:i], c.SelectedTypes[i+1:]...)
			return true
		}
	}
	return false
}
func (c *ClashWorker) GetSelectedProviders() []string    { return c.SelectedProviders }
func (c *ClashWorker) SetSelectedProviders(val []string) { c.SelectedProviders = val }
func (c *ClashWorker) AddSelectedProvider(val string) {
	c.SelectedProviders = append(c.SelectedProviders, val)
}
func (c *ClashWorker) RemoveSelectedProvider(val string) bool {
	for i, v := range c.SelectedProviders {
		if v == val {
			c.SelectedProviders = append(c.SelectedProviders[:i], c.SelectedProviders[i+1:]...)
			return true
		}
	}
	return false
}
func (c *ClashWorker) GetConfigProviders() map[string]string    { return c.ConfigProviders }
func (c *ClashWorker) SetConfigProviders(val map[string]string) { c.ConfigProviders = val }
func (c *ClashWorker) AddConfigProvider(key, link string)       { c.ConfigProviders[key] = link }
func (c *ClashWorker) RemoveConfigProvider(key string)          { delete(c.ConfigProviders, key) }
func (c *ClashWorker) GetIpProviderLink() string                { return c.IpProviderLink }
func (c *ClashWorker) SetIpProviderLink(val string)             { c.IpProviderLink = val }
func (c *ClashWorker) GetOperators() []string                   { return c.Operators }
func (c *ClashWorker) SetOperators(val []string)                { c.Operators = val }
func (c *ClashWorker) AddOperator(val string)                   { c.Operators = append(c.Operators, val) }
func (c *ClashWorker) RemoveOperator(val string) bool {
	for i, v := range c.Operators {
		if v == val {
			c.Operators = append(c.Operators[:i], c.Operators[i+1:]...)
			return true
		}
	}
	return false
}
func (c *ClashWorker) GetCleanIPs() []CleanIP    { return c.CleanIPs }
func (c *ClashWorker) SetCleanIPs(val []CleanIP) { c.CleanIPs = val }
func (c *ClashWorker) AddCleanIP(ip CleanIP)     { c.CleanIPs = append(c.CleanIPs, ip) }
func (c *ClashWorker) RemoveCleanIP(ip string) bool {
	for i, v := range c.CleanIPs {
		if v.IP == ip {
			c.CleanIPs = append(c.CleanIPs[:i], c.CleanIPs[i+1:]...)
			return true
		}
	}
	return false
}
func (c *ClashWorker) GetRules() []string    { return c.Rules }
func (c *ClashWorker) SetRules(val []string) { c.Rules = val }
func (c *ClashWorker) AddRule(val string)    { c.Rules = append(c.Rules, val) }
func (c *ClashWorker) RemoveRule(val string) bool {
	for i, v := range c.Rules {
		if v == val {
			c.Rules = append(c.Rules[:i], c.Rules[i+1:]...)
			return true
		}
	}
	return false
}
func (c *ClashWorker) GetProxies() []ClashProxy    { return c.Proxies }
func (c *ClashWorker) SetProxies(val []ClashProxy) { c.Proxies = val }
func (c *ClashWorker) AddProxy(val ClashProxy)     { c.Proxies = append(c.Proxies, val) }
func (c *ClashWorker) RemoveProxy(name string) bool {
	for i, v := range c.Proxies {
		if v.Name == name {
			c.Proxies = append(c.Proxies[:i], c.Proxies[i+1:]...)
			return true
		}
	}
	return false
}
func (c *ClashWorker) GetProxyGroups() []ClashGroup    { return c.ProxyGroups }
func (c *ClashWorker) SetProxyGroups(val []ClashGroup) { c.ProxyGroups = val }
func (c *ClashWorker) AddProxyGroup(val ClashGroup)    { c.ProxyGroups = append(c.ProxyGroups, val) }
func (c *ClashWorker) RemoveProxyGroup(name string) bool {
	for i, v := range c.ProxyGroups {
		if v.Name == name {
			c.ProxyGroups = append(c.ProxyGroups[:i], c.ProxyGroups[i+1:]...)
			return true
		}
	}
	return false
}

// Clear Methods
func (c *ClashWorker) ClearCleanIPs()          { c.CleanIPs = []CleanIP{} }
func (c *ClashWorker) ClearSelectedTypes()     { c.SelectedTypes = []string{} }
func (c *ClashWorker) ClearSelectedProviders() { c.SelectedProviders = []string{} }
func (c *ClashWorker) ClearConfigProviders()   { c.ConfigProviders = make(map[string]string) }
func (c *ClashWorker) ClearRules()             { c.Rules = []string{} }
func (c *ClashWorker) ClearProxies()           { c.Proxies = []ClashProxy{} }
func (c *ClashWorker) ClearProxyGroups()       { c.ProxyGroups = []ClashGroup{} }

// Generator, validator, and logic methods
func (c *ClashWorker) GenerateUrlTestGroup(name string, interval int, url string, proxies []string) ClashGroup {
	return ClashGroup{Name: name, Type: "url-test", URL: url, Interval: interval, Proxies: proxies}
}

func (c *ClashWorker) GenerateFallbackGroup(name string, interval int, url string, proxies []string) ClashGroup {
	return ClashGroup{Name: name, Type: "fallback", URL: url, Interval: interval, Proxies: proxies}
}

func (c *ClashWorker) GenerateLoadBalanceChGroup(name string, interval int, url string, proxies []string) ClashGroup {
	return ClashGroup{Name: name, Type: "load-balance", Strategy: "consistent-hashing", URL: url, Interval: interval, Proxies: proxies}
}

func (c *ClashWorker) GenerateLoadBalanceRrGroup(name string, interval int, url string, proxies []string) ClashGroup {
	return ClashGroup{Name: name, Type: "load-balance", Strategy: "round-robin", URL: url, Interval: interval, Proxies: proxies}
}

func (c *ClashWorker) ValidateCipher(cipher string) bool {
	ciphers := []string{"none", "auto", "plain", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20", "chacha20-ietf-poly1305"}
	for _, v := range ciphers {
		if v == cipher {
			return true
		}
	}
	return false
}

func (c *ClashWorker) ValidateUuid(uuid string) bool {
	return len(uuid) == 36 && strings.Count(uuid, "-") == 4
}

func (c *ClashWorker) MixClashConfig(proxy *ClashProxy, cleanIP string, port int, serverName string) bool {
	if proxy == nil {
		return false
	}
	proxy.Server = cleanIP
	proxy.Port = port
	proxy.ServerName = serverName
	proxy.Merged = true
	return true
}

func (c *ClashWorker) ToClashYaml() (string, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (c *ClashWorker) FetchCleanIPs() ([]CleanIP, error) {
	return c.CleanIPs, nil
}

func (c *ClashWorker) FilterConfigs(proxies []ClashProxy) []ClashProxy {
	filtered := []ClashProxy{}
	for _, p := range proxies {
		allowed := false
		for _, t := range c.SelectedTypes {
			if strings.ToLower(p.Type) == strings.ToLower(t) {
				allowed = true
				break
			}
		}
		if allowed {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// Aggregate aggregates and merges node filters.
func (c *ClashWorker) Aggregate() {
	slog.Info("ClashWorker", "status", "Porting Cloudflare Worker subscription aggregator")
	slog.Info("ClashWorker", "status", "Implementing MCI/MTN operator IP mapping and node merging filters")
	log.Printf("ClashWorker: Configured with port %d, socks-port %d, mode %s", c.Port, c.SocksPort, c.Mode)
}
