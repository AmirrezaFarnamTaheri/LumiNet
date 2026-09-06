package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

// SingboxExportOptions configures client-side sing-box JSON compilation.
type SingboxExportOptions struct {
	Listen              string `json:"listen"`
	MixedPort           int    `json:"mixed_port"`
	TunEnabled          bool   `json:"tun_enabled"`
	TunMTU              int    `json:"tun_mtu"`
	AutoURLTest         bool   `json:"auto_urltest"`
	TestURL             string `json:"test_url"`
	ExperimentalClashAPI bool  `json:"experimental_clash_api"`
	ClashAPIPort        int    `json:"clash_api_port"`
}

// DefaultSingboxExportOptions returns recommended production client defaults.
func DefaultSingboxExportOptions() SingboxExportOptions {
	return SingboxExportOptions{
		Listen:              "127.0.0.1",
		MixedPort:           2080,
		TunEnabled:          false,
		TunMTU:              9000,
		AutoURLTest:         true,
		TestURL:             "https://www.gstatic.com/generate_204",
		ExperimentalClashAPI: true,
		ClashAPIPort:        9090,
	}
}

// ParseMultiProtocolSubscription ingests raw multi-line or base64-encoded subscription strings.
func ParseMultiProtocolSubscription(raw string) ([]*proxyconfig.ProxyConfig, []string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	// Try base64 decoding if not starting with protocol scheme
	if !strings.Contains(trimmed, "://") {
		if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
			trimmed = string(decoded)
		} else if decoded, err := base64.URLEncoding.DecodeString(trimmed); err == nil {
			trimmed = string(decoded)
		}
	}

	lines := strings.Split(trimmed, "\n")
	configs := make([]*proxyconfig.ProxyConfig, 0, len(lines))
	warnings := make([]string, 0)
	seenTags := make(map[string]int)

	for lineIdx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		cfg, err := proxyconfig.ParseProxyURI(line)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d: %v", lineIdx+1, err))
			continue
		}

		// Ensure tag is non-empty and unique
		tag := strings.TrimSpace(cfg.Name)
		if tag == "" {
			tag = string(cfg.Protocol)
		}
		baseTag := tag
		counter := 1
		for seenTags[tag] > 0 {
			tag = fmt.Sprintf("%s-%d", baseTag, counter)
			counter++
		}
		seenTags[tag] = 1
		cfg.Name = tag

		configs = append(configs, cfg)
	}

	return configs, warnings
}

// ExportSingboxClientConfig compiles a slice of ProxyConfigs into sing-box 1.10+ / 1.13+ client JSON.
func ExportSingboxClientConfig(configs []*proxyconfig.ProxyConfig, opts SingboxExportOptions) ([]byte, error) {
	outbounds := make([]map[string]any, 0, len(configs)+4)
	tags := make([]string, 0, len(configs))

	for _, cfg := range configs {
		if cfg == nil {
			continue
		}
		ob := buildSingboxOutboundFromConfig(cfg)
		outbounds = append(outbounds, ob)
		tags = append(tags, cfg.Name)
	}

	selectorOutbounds := make([]string, 0, len(tags)+2)
	if opts.AutoURLTest && len(tags) > 0 {
		selectorOutbounds = append(selectorOutbounds, "auto")
	}
	selectorOutbounds = append(selectorOutbounds, tags...)
	selectorOutbounds = append(selectorOutbounds, "direct")

	allOutbounds := make([]map[string]any, 0, len(outbounds)+5)

	defaultSelector := "select"
	if opts.AutoURLTest && len(tags) > 0 {
		defaultSelector = "auto"
	}

	// 1. Selector
	allOutbounds = append(allOutbounds, map[string]any{
		"type":      "selector",
		"tag":       "select",
		"outbounds": selectorOutbounds,
		"default":   defaultSelector,
	})

	// 2. URLTest
	if opts.AutoURLTest && len(tags) > 0 {
		allOutbounds = append(allOutbounds, map[string]any{
			"type":         "urltest",
			"tag":          "auto",
			"outbounds":    tags,
			"url":          opts.TestURL,
			"interval":     "3m",
			"tolerance":    50,
			"idle_timeout": "30m",
		})
	}

	// 3. User node outbounds
	allOutbounds = append(allOutbounds, outbounds...)

	// 4. Built-ins
	allOutbounds = append(allOutbounds, map[string]any{"type": "direct", "tag": "direct"})
	allOutbounds = append(allOutbounds, map[string]any{"type": "block", "tag": "block"})
	allOutbounds = append(allOutbounds, map[string]any{"type": "dns", "tag": "dns-out"})

	// Inbounds
	inbounds := make([]map[string]any, 0, 2)
	if opts.TunEnabled {
		mtu := opts.TunMTU
		if mtu <= 0 {
			mtu = 9000
		}
		inbounds = append(inbounds, map[string]any{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"mtu":          mtu,
			"auto_route":   true,
			"strict_route": true,
			"stack":        "system",
			"dns_mode":     "hijack",
			"dns_address":  []string{"172.19.0.2", "fdfe:dcba:9876::2"},
		})
	}

	listenAddr := opts.Listen
	if listenAddr == "" {
		listenAddr = "127.0.0.1"
	}
	mixedPort := opts.MixedPort
	if mixedPort <= 0 {
		mixedPort = 2080
	}
	inbounds = append(inbounds, map[string]any{
		"type":             "mixed",
		"tag":              "mixed-in",
		"listen":           listenAddr,
		"listen_port":      mixedPort,
		"set_system_proxy": false,
	})

	root := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers": []map[string]any{
				{"tag": "google", "address": "tls://8.8.8.8", "detour": "select"},
				{"tag": "local", "address": "223.5.5.5", "detour": "direct"},
			},
			"rules": []map[string]any{
				{"outbound": []string{"any"}, "server": "local"},
			},
			"final":           "google",
			"strategy":        "prefer_ipv4",
			"optimistic":      true,
			"reverse_mapping": true,
		},
		"inbounds":  inbounds,
		"outbounds": allOutbounds,
		"route": map[string]any{
			"rules": []map[string]any{
				{"ip_is_private": true, "outbound": "direct"},
				{"protocol": "dns", "action": "hijack-dns"},
				{"action": "route", "outbound": "select"},
			},
			"final":                 "select",
			"auto_detect_interface": true,
		},
	}

	if opts.ExperimentalClashAPI {
		apiPort := opts.ClashAPIPort
		if apiPort <= 0 {
			apiPort = 9090
		}
		root["experimental"] = map[string]any{
			"cache_file": map[string]any{
				"enabled":   true,
				"path":      "cache.db",
				"store_dns": true,
			},
			"clash_api": map[string]any{
				"external_controller":                  fmt.Sprintf("127.0.0.1:%d", apiPort),
				"access_control_allow_origin":          []string{"*"},
				"access_control_allow_private_network": true,
			},
		}
	}

	return json.MarshalIndent(root, "", "  ")
}

func buildSingboxOutboundFromConfig(cfg *proxyconfig.ProxyConfig) map[string]any {
	ob := map[string]any{
		"type":        string(cfg.Protocol),
		"tag":         cfg.Name,
		"server":      cfg.Address,
		"server_port": cfg.Port,
	}

	switch cfg.Protocol {
	case proxyconfig.ProtocolVMess:
		ob["uuid"] = cfg.UUID
		ob["alter_id"] = cfg.AlterID
		cipher := cfg.Security
		if cipher == "" {
			cipher = "auto"
		}
		ob["security"] = cipher
		ob["global_padding"] = false
		ob["authenticated_length"] = true
	case proxyconfig.ProtocolVLESS:
		ob["uuid"] = cfg.UUID
		if cfg.Flow != "" {
			ob["flow"] = cfg.Flow
		}
		ob["packet_encoding"] = "xudp"
	case proxyconfig.ProtocolTrojan:
		ob["password"] = cfg.Password
	case proxyconfig.ProtocolShadowsocks:
		ob["method"] = cfg.Method
		ob["password"] = cfg.Password
		if cfg.Plugin != "" {
			ob["plugin"] = cfg.Plugin
			ob["plugin_opts"] = cfg.PluginOpts
		}
	case proxyconfig.ProtocolHysteria2:
		ob["password"] = cfg.Password
		if cfg.Obfs != "" {
			ob["obfs"] = map[string]any{
				"type":     "salamander",
				"password": cfg.Obfs,
			}
		}
	case proxyconfig.ProtocolTUIC:
		ob["uuid"] = cfg.UUID
		ob["password"] = cfg.Password
		ob["congestion_control"] = "cubic"
		ob["udp_relay_mode"] = "native"
	case proxyconfig.ProtocolWireGuard:
		ob["local_address"] = []string{"10.0.0.2/32"}
		ob["private_key"] = cfg.PrivateKey
		ob["peer_public_key"] = cfg.PublicKey
		ob["reserved"] = []int{0, 0, 0}
		ob["mtu"] = 1408
	}

	if cfg.TLS || cfg.Security == "tls" || cfg.Security == "reality" {
		tls := map[string]any{"enabled": true}
		if cfg.SNI != "" {
			tls["server_name"] = cfg.SNI
		}
		if cfg.SkipCertVerify {
			tls["insecure"] = true
		}
		if len(cfg.ALPN) > 0 {
			tls["alpn"] = cfg.ALPN
		}
		if cfg.Fingerprint != "" {
			tls["utls"] = map[string]any{
				"enabled":     true,
				"fingerprint": cfg.Fingerprint,
			}
		}
		if cfg.Security == "reality" {
			tls["reality"] = map[string]any{
				"enabled":    true,
				"public_key": cfg.PublicKey,
				"short_id":   cfg.ShortID,
			}
		}
		ob["tls"] = tls
	}

	transport := strings.ToLower(cfg.Transport)
	if transport != "" && transport != "tcp" {
		tr := map[string]any{"type": transport}
		switch transport {
		case "ws", "websocket":
			tr["type"] = "ws"
			if cfg.Path != "" {
				tr["path"] = cfg.Path
			}
			if cfg.Host != "" {
				tr["headers"] = map[string]string{"Host": cfg.Host}
			}
		case "grpc":
			tr["service_name"] = cfg.ServiceName
		case "http", "h2":
			tr["type"] = "http"
			if cfg.Path != "" {
				tr["path"] = cfg.Path
			}
			if cfg.Host != "" {
				tr["host"] = []string{cfg.Host}
			}
		}
		ob["transport"] = tr
	}

	return ob
}

// UnescapeURLQuery unescapes query components cleanly.
func UnescapeURLQuery(s string) string {
	if unquoted, err := url.QueryUnescape(s); err == nil {
		return unquoted
	}
	return s
}
