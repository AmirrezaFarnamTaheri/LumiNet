package proxyconfig

import (
	"fmt"
)

// DomainStrategy defines the address resolution behavior in core routing.
type DomainStrategy string

const (
	DomainStrategyAsIs         DomainStrategy = "AsIs"
	DomainStrategyIPIfNonMatch DomainStrategy = "IPIfNonMatch"
	DomainStrategyIPOnDemand   DomainStrategy = "IPOnDemand"
)

// ChainedHop describes one proxy node participating in a multi-hop proxy chain.
type ChainedHop struct {
	Tag      string
	Protocol string
	Address  string
	Port     int
	Settings map[string]any
}

// BuildProxyChain constructs linked proxy outbounds where hop[i] routes through hop[i+1].
func BuildProxyChain(hops []ChainedHop) []map[string]any {
	if len(hops) == 0 {
		return nil
	}

	outbounds := make([]map[string]any, len(hops))
	for i, hop := range hops {
		settings := hop.Settings
		if settings == nil {
			settings = map[string]any{
				"vnext": []map[string]any{
					{
						"address": hop.Address,
						"port":    hop.Port,
					},
				},
			}
		}

		ob := map[string]any{
			"tag":      hop.Tag,
			"protocol": hop.Protocol,
			"settings": settings,
		}

		// If not the final exit hop, point dialerProxy to next hop
		if i+1 < len(hops) {
			ob["streamSettings"] = map[string]any{
				"sockopt": map[string]any{
					"dialerProxy": hops[i+1].Tag,
				},
			}
		}

		outbounds[i] = ob
	}

	return outbounds
}

// BuildSplitDNS generates DNS server mapping domestic domains to local DNS and
// foreign/blocked domains to encrypted DoH/DoT endpoints.
func BuildSplitDNS(directDomains []string, directDNS, remoteDNS string) map[string]any {
	servers := []any{
		map[string]any{
			"address": remoteDNS,
			"domains": []string{"geosite:geolocation-!cn", "geosite:google", "geosite:netflix"},
		},
	}

	if len(directDomains) > 0 {
		servers = append(servers, map[string]any{
			"address":   directDNS,
			"domains":   directDomains,
			"expectIPs": []string{"geoip:cn", "geoip:ir", "geoip:private"},
		})
	}

	// Fallback server
	servers = append(servers, directDNS)

	return map[string]any{
		"servers":       servers,
		"queryStrategy": "UseIP",
	}
}

// CompileRegionalRoutingRules generates deterministic geosite/geoip rules for domestic bypass.
func CompileRegionalRoutingRules(bypassIran, bypassRussia, bypassChina bool) []map[string]any {
	var rules []map[string]any

	// Adblock always blocks
	rules = append(rules, map[string]any{
		"type":        "field",
		"domain":      []string{"geosite:category-ads-all"},
		"outboundTag": "block",
	})

	// Private IP bypass
	rules = append(rules, map[string]any{
		"type":        "field",
		"ip":          []string{"geoip:private"},
		"outboundTag": "direct",
	})

	if bypassIran {
		rules = append(rules, map[string]any{
			"type":        "field",
			"domain":      []string{"geosite:ir", "domain:.ir"},
			"ip":          []string{"geoip:ir"},
			"outboundTag": "direct",
		})
	}

	if bypassRussia {
		rules = append(rules, map[string]any{
			"type":        "field",
			"domain":      []string{"geosite:ru", "domain:.ru"},
			"ip":          []string{"geoip:ru"},
			"outboundTag": "direct",
		})
	}

	if bypassChina {
		rules = append(rules, map[string]any{
			"type":        "field",
			"domain":      []string{"geosite:cn", "domain:.cn"},
			"ip":          []string{"geoip:cn"},
			"outboundTag": "direct",
		})
	}

	return rules
}

// BuildSpeedtestConfig produces a stripped down configuration for fast latency probing.
func BuildSpeedtestConfig(fullConfig map[string]any, targetOutboundTag string, probePort int) (map[string]any, error) {
	outboundsRaw, ok := fullConfig["outbounds"].([]map[string]any)
	if !ok {
		if obList, okList := fullConfig["outbounds"].([]any); okList {
			for _, item := range obList {
				if m, okMap := item.(map[string]any); okMap {
					outboundsRaw = append(outboundsRaw, m)
				}
			}
		}
	}

	var selectedOutbounds []map[string]any
	for _, ob := range outboundsRaw {
		tag, _ := ob["tag"].(string)
		if tag == targetOutboundTag || tag == "direct" {
			selectedOutbounds = append(selectedOutbounds, ob)
		}
	}

	if len(selectedOutbounds) == 0 {
		return nil, fmt.Errorf("target outbound tag '%s' not found", targetOutboundTag)
	}

	speedtestInbound := map[string]any{
		"tag":      "speedtest_inbound",
		"listen":   "127.0.0.1",
		"port":     probePort,
		"protocol": "socks",
		"settings": map[string]any{
			"auth": "noauth",
			"udp":  false,
		},
	}

	return map[string]any{
		"log": map[string]any{
			"loglevel": "warning",
		},
		"inbounds":  []map[string]any{speedtestInbound},
		"outbounds": selectedOutbounds,
		"routing": map[string]any{
			"domainStrategy": string(DomainStrategyAsIs),
			"rules": []map[string]any{
				{
					"type":        "field",
					"inboundTag":  []string{"speedtest_inbound"},
					"outboundTag": targetOutboundTag,
				},
			},
		},
	}, nil
}
