// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: v2rayCustomRoutingList-master
// Target path: server/internal/proxy/custom_routing_rules.go

package proxy

// V2RayRoutingRule represents a V2Ray routing rule entry.
type V2RayRoutingRule struct {
	Type        string   `json:"type,omitempty"`
	OutboundTag string   `json:"outboundTag"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	Protocol    []string `json:"protocol,omitempty"`
	Enabled     bool     `json:"enabled"`
	Remarks     string   `json:"remarks,omitempty"`
}

// CustomRoutingRules implements the custom geosite routing lists.
type CustomRoutingRules struct {
	Rules []V2RayRoutingRule
}

// NewCustomRoutingRules instantiates the custom routing manager with defaults.
func NewCustomRoutingRules() *CustomRoutingRules {
	mgr := &CustomRoutingRules{}
	mgr.loadDefaultRules()
	return mgr
}

// GetRules returns the registered routing rules.
func (c *CustomRoutingRules) GetRules() []V2RayRoutingRule {
	return c.Rules
}

// AddRule appends a new rule to the engine.
func (c *CustomRoutingRules) AddRule(rule V2RayRoutingRule) {
	c.Rules = append(c.Rules, rule)
}

// Route performs diagnostic triggers.
func (c *CustomRoutingRules) Route() {
	// Diagnostic route stub
}

// loadDefaultRules loads default routing parameters from v2rayCustomRoutingList.
func (c *CustomRoutingRules) loadDefaultRules() {
	c.Rules = []V2RayRoutingRule{
		{
			Remarks:     "Block UDP 443 (QUIC detour)",
			OutboundTag: "block",
			Port:        "443",
			Network:     "udp",
			Enabled:     true,
		},
		{
			Remarks:     "Bypass BitTorrent",
			OutboundTag: "direct",
			Protocol:    []string{"bittorrent"},
			Enabled:     true,
		},
		{
			Remarks:     "Bypass Local IPs",
			OutboundTag: "direct",
			IP:          []string{"geoip:private"},
			Enabled:     true,
		},
		{
			Remarks:     "Bypass Local Domains",
			OutboundTag: "direct",
			Domain:      []string{"geosite:private"},
			Enabled:     true,
		},
		{
			Remarks:     "Proxy Foreign Public DNS",
			OutboundTag: "proxy",
			IP: []string{
				"1.1.1.1",
				"1.0.0.1",
				"8.8.8.8",
				"8.8.4.4",
				"9.9.9.9",
			},
			Enabled: true,
		},
		{
			Remarks:     "Default Final Catch-All Proxy",
			OutboundTag: "proxy",
			Port:        "0-65535",
			Enabled:     true,
		},
	}
}
