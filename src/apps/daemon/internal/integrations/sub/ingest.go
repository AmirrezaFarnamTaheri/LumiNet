package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
	"gopkg.in/yaml.v3"
)

// ParseContent is the canonical subscription payload parser. It owns format
// detection while proxyconfig owns per-node URI semantics.
func ParseContent(content string) ([]*proxyconfig.ProxyConfig, error) {
	// Outline invite pages can carry a static ss:// access key in their URL fragment.
	// Unwrap locally before format detection; this never fetches the invite URL.
	if unwrapped, ok, err := unwrapOutlineStaticInvite(content); err != nil {
		return nil, err
	} else if ok {
		return proxyconfig.ParseProxyList(unwrapped)
	}
	// 0. Try LumiNet's versioned canonical bundle before generic formats.
	if configs, err := parseLumiNetBundle([]byte(content)); err == nil && len(configs) > 0 {
		return configs, nil
	}

	// 1. Try Base64 parsing
	if configs, err := parseBase64Content(content); err == nil && len(configs) > 0 {
		return configs, nil
	}

	// 2. Try Clash Config parsing
	if configs, err := parseClashConfig([]byte(content)); err == nil && len(configs) > 0 {
		return configs, nil
	}

	// 3. Try SingBox config parsing
	if configs, err := parseSingBoxOutbounds([]byte(content)); err == nil && len(configs) > 0 {
		return configs, nil
	}

	// 4. Fallback: Parse plain text URI list directly
	return proxyconfig.ParseProxyList(content)
}

func parseLumiNetBundle(data []byte) ([]*proxyconfig.ProxyConfig, error) {
	var bundle struct {
		Schema string                     `json:"schema"`
		Nodes  []*proxyconfig.ProxyConfig `json:"nodes"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, err
	}
	if bundle.Schema != "luminet.proxy-bundle.v1" {
		return nil, fmt.Errorf("unsupported LumiNet proxy bundle schema %q", bundle.Schema)
	}
	if len(bundle.Nodes) == 0 {
		return nil, fmt.Errorf("LumiNet proxy bundle has no nodes")
	}
	if len(bundle.Nodes) > maxConversionNodes {
		return nil, fmt.Errorf("LumiNet proxy bundle exceeds %d nodes", maxConversionNodes)
	}
	for i, cfg := range bundle.Nodes {
		if cfg == nil {
			return nil, fmt.Errorf("LumiNet proxy bundle node %d is nil", i+1)
		}
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("LumiNet proxy bundle node %d: %w", i+1, err)
		}
	}
	return bundle.Nodes, nil
}

// ParseBase64Subscription decodes a base64-encoded subscription body
// containing one proxy URI per line and parses each URI.
func parseBase64Content(data string) ([]*proxyconfig.ProxyConfig, error) {
	decoded, err := decodeBase64Mixed(data)
	if err != nil {
		return nil, err
	}
	return proxyconfig.ParseProxyList(decoded)
}

// ParseClashConfig parses a Clash-format YAML configuration and extracts
// proxy configurations from the 'proxies' section.
func parseClashConfig(yamlData []byte) ([]*proxyconfig.ProxyConfig, error) {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(yamlData, &raw); err != nil {
		return nil, err
	}

	proxiesVal, ok := raw["proxies"]
	if !ok {
		return nil, fmt.Errorf("missing 'proxies' section in Clash config")
	}

	proxiesList, ok := proxiesVal.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'proxies' section is not a list")
	}

	var configs []*proxyconfig.ProxyConfig
	for _, p := range proxiesList {
		pMap, ok := p.(map[string]interface{})
		if !ok {
			continue
		}

		cfg := &proxyconfig.ProxyConfig{}

		if t, exists := pMap["type"]; exists {
			ts := fmt.Sprintf("%v", t)
			switch ts {
			case "ss":
				cfg.Protocol = proxyconfig.ProtocolShadowsocks
			case "vmess":
				cfg.Protocol = proxyconfig.ProtocolVMess
			case "vless":
				cfg.Protocol = proxyconfig.ProtocolVLESS
			case "trojan":
				cfg.Protocol = proxyconfig.ProtocolTrojan
			case "socks5":
				cfg.Protocol = proxyconfig.ProtocolSOCKS5
			case "http":
				cfg.Protocol = proxyconfig.ProtocolHTTP
			case "hysteria2", "hy2":
				cfg.Protocol = proxyconfig.ProtocolHysteria2
			case "tuic":
				cfg.Protocol = proxyconfig.ProtocolTUIC
			case "wireguard":
				cfg.Protocol = proxyconfig.ProtocolWireGuard
			case "awg", "amneziawg":
				cfg.Protocol = proxyconfig.ProtocolAmneziaWG
			case "naive":
				cfg.Protocol = proxyconfig.ProtocolNaive
			case "anytls":
				cfg.Protocol = proxyconfig.ProtocolAnyTLS
			case "juicity":
				cfg.Protocol = proxyconfig.ProtocolJuicity
			default:
				continue
			}
		}

		if name, exists := pMap["name"]; exists {
			cfg.Name = fmt.Sprintf("%v", name)
		}

		if server, exists := pMap["server"]; exists {
			cfg.Address = fmt.Sprintf("%v", server)
		}

		if port, exists := pMap["port"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", port), "%d", &cfg.Port)
		}

		if uuidVal, exists := pMap["uuid"]; exists {
			cfg.UUID = fmt.Sprintf("%v", uuidVal)
		}

		if pass, exists := pMap["password"]; exists {
			cfg.Password = fmt.Sprintf("%v", pass)
		}

		if cipher, exists := pMap["cipher"]; exists {
			cfg.Method = fmt.Sprintf("%v", cipher)
		}

		if pk, exists := pMap["private-key"]; exists {
			cfg.PrivateKey = fmt.Sprintf("%v", pk)
		}
		if pubk, exists := pMap["public-key"]; exists {
			cfg.PublicKey = fmt.Sprintf("%v", pubk)
		}
		if ipVal, exists := pMap["ip"]; exists {
			cfg.LocalAddress = []string{fmt.Sprintf("%v", ipVal)}
		}
		if mtuVal, exists := pMap["mtu"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", mtuVal), "%d", &cfg.MTU)
		}
		if resVal, exists := pMap["reserved"]; exists {
			cfg.Reserved = parseReservedField(resVal)
		}

		if val, exists := pMap["wnoise"]; exists {
			cfg.WNoise = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["wnoisecount"]; exists {
			cfg.WNoiseCount = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["wpayloadsize"]; exists {
			cfg.WPayloadSize = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["wnoisedelay"]; exists {
			cfg.WNoiseDelay = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["fake-packets"]; exists {
			cfg.FakePackets = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["fake_packets"]; exists {
			cfg.FakePackets = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["ifp"]; exists {
			cfg.FakePackets = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["fake-packets-size"]; exists {
			cfg.FakePacketsSize = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["fake_packets_size"]; exists {
			cfg.FakePacketsSize = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["ifps"]; exists {
			cfg.FakePacketsSize = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["fake-packets-delay"]; exists {
			cfg.FakePacketsDelay = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["fake_packets_delay"]; exists {
			cfg.FakePacketsDelay = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["ifpd"]; exists {
			cfg.FakePacketsDelay = fmt.Sprintf("%v", val)
		}
		if val, exists := pMap["fake-packets-mode"]; exists {
			cfg.FakePacketsMode = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["fake_packets_mode"]; exists {
			cfg.FakePacketsMode = fmt.Sprintf("%v", val)
		} else if val, exists := pMap["ifpm"]; exists {
			cfg.FakePacketsMode = fmt.Sprintf("%v", val)
		}

		if awgOptVal, exists := pMap["amnezia-wg-option"]; exists {
			if awgMap, ok := awgOptVal.(map[string]interface{}); ok {
				cfg.Protocol = proxyconfig.ProtocolAmneziaWG
				if val, ok := awgMap["jc"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jc)
				}
				if val, ok := awgMap["jmin"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmin)
				}
				if val, ok := awgMap["jmax"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmax)
				}
				if val, ok := awgMap["s1"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S1)
				}
				if val, ok := awgMap["s2"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S2)
				}
				if val, ok := awgMap["s3"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S3)
				}
				if val, ok := awgMap["s4"]; ok {
					fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S4)
				}
				if val, ok := awgMap["h1"]; ok {
					cfg.H1 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["h2"]; ok {
					cfg.H2 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["h3"]; ok {
					cfg.H3 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["h4"]; ok {
					cfg.H4 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["i1"]; ok {
					cfg.I1 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["i2"]; ok {
					cfg.I2 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["i3"]; ok {
					cfg.I3 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["i4"]; ok {
					cfg.I4 = fmt.Sprintf("%v", val)
				}
				if val, ok := awgMap["i5"]; ok {
					cfg.I5 = fmt.Sprintf("%v", val)
				}
			}
		}

		applyClashImportedFields(cfg, pMap)
		if err := cfg.Validate(); err == nil {
			configs = append(configs, cfg)
		}
	}

	return configs, nil
}

// ParseSingBoxOutbounds parses a sing-box JSON configuration and extracts
// proxy configurations from the 'outbounds' array.
func parseSingBoxOutbounds(jsonData []byte) ([]*proxyconfig.ProxyConfig, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(jsonData, &raw); err != nil {
		return nil, err
	}

	outboundsVal, ok := raw["outbounds"]
	if !ok {
		return nil, fmt.Errorf("missing 'outbounds' section in sing-box config")
	}

	outboundsList, ok := outboundsVal.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'outbounds' section is not a list")
	}

	var configs []*proxyconfig.ProxyConfig
	for _, o := range outboundsList {
		oMap, ok := o.(map[string]interface{})
		if !ok {
			continue
		}

		cfg := &proxyconfig.ProxyConfig{}

		if t, exists := oMap["type"]; exists {
			ts := fmt.Sprintf("%v", t)
			switch ts {
			case "shadowsocks":
				cfg.Protocol = proxyconfig.ProtocolShadowsocks
			case "vmess":
				cfg.Protocol = proxyconfig.ProtocolVMess
			case "vless":
				cfg.Protocol = proxyconfig.ProtocolVLESS
			case "trojan":
				cfg.Protocol = proxyconfig.ProtocolTrojan
			case "socks":
				cfg.Protocol = proxyconfig.ProtocolSOCKS5
			case "http":
				cfg.Protocol = proxyconfig.ProtocolHTTP
			case "hysteria2":
				cfg.Protocol = proxyconfig.ProtocolHysteria2
			case "tuic":
				cfg.Protocol = proxyconfig.ProtocolTUIC
			case "wireguard":
				cfg.Protocol = proxyconfig.ProtocolWireGuard
			case "awg", "amneziawg":
				cfg.Protocol = proxyconfig.ProtocolAmneziaWG
			case "naive":
				cfg.Protocol = proxyconfig.ProtocolNaive
			case "anytls":
				cfg.Protocol = proxyconfig.ProtocolAnyTLS
			case "juicity":
				cfg.Protocol = proxyconfig.ProtocolJuicity
			case "dnstt":
				cfg.Protocol = proxyconfig.ProtocolDNSTT
			default:
				continue
			}
		}

		if tag, exists := oMap["tag"]; exists {
			cfg.Name = fmt.Sprintf("%v", tag)
		}

		if detour, exists := oMap["detour"]; exists {
			cfg.DialerProxy = fmt.Sprintf("%v", detour)
		} else if dProxy, exists := oMap["dialer_proxy"]; exists {
			cfg.DialerProxy = fmt.Sprintf("%v", dProxy)
		}

		if server, exists := oMap["server"]; exists {
			cfg.Address = fmt.Sprintf("%v", server)
		}

		if port, exists := oMap["server_port"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", port), "%d", &cfg.Port)
		}

		if uuidVal, exists := oMap["uuid"]; exists {
			cfg.UUID = fmt.Sprintf("%v", uuidVal)
		}

		if pass, exists := oMap["password"]; exists {
			cfg.Password = fmt.Sprintf("%v", pass)
		}

		if method, exists := oMap["method"]; exists {
			cfg.Method = fmt.Sprintf("%v", method)
		}

		if pk, exists := oMap["private_key"]; exists {
			cfg.PrivateKey = fmt.Sprintf("%v", pk)
		}
		if pubk, exists := oMap["peer_public_key"]; exists {
			cfg.PublicKey = fmt.Sprintf("%v", pubk)
		}
		if localAddrsVal, exists := oMap["local_address"]; exists {
			if list, ok := localAddrsVal.([]interface{}); ok {
				var addrs []string
				for _, a := range list {
					addrs = append(addrs, fmt.Sprintf("%v", a))
				}
				cfg.LocalAddress = addrs
			} else if str, ok := localAddrsVal.(string); ok {
				cfg.LocalAddress = []string{str}
			}
		}
		if mtuVal, exists := oMap["mtu"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", mtuVal), "%d", &cfg.MTU)
		}
		if resVal, exists := oMap["reserved"]; exists {
			cfg.Reserved = parseReservedField(resVal)
		}

		if val, exists := oMap["wnoise"]; exists {
			cfg.WNoise = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["wnoisecount"]; exists {
			cfg.WNoiseCount = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["wpayloadsize"]; exists {
			cfg.WPayloadSize = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["wnoisedelay"]; exists {
			cfg.WNoiseDelay = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["fake_packets"]; exists {
			cfg.FakePackets = fmt.Sprintf("%v", val)
		} else if val, exists := oMap["ifp"]; exists {
			cfg.FakePackets = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["fake_packets_size"]; exists {
			cfg.FakePacketsSize = fmt.Sprintf("%v", val)
		} else if val, exists := oMap["ifps"]; exists {
			cfg.FakePacketsSize = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["fake_packets_delay"]; exists {
			cfg.FakePacketsDelay = fmt.Sprintf("%v", val)
		} else if val, exists := oMap["ifpd"]; exists {
			cfg.FakePacketsDelay = fmt.Sprintf("%v", val)
		}
		if val, exists := oMap["fake_packets_mode"]; exists {
			cfg.FakePacketsMode = fmt.Sprintf("%v", val)
		} else if val, exists := oMap["ifpm"]; exists {
			cfg.FakePacketsMode = fmt.Sprintf("%v", val)
		}

		// Check for AmneziaWG properties in sing-box outbound
		isAmnezia := false
		if val, exists := oMap["awg_jc"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jc)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_jc"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jc)
			isAmnezia = true
		}

		if val, exists := oMap["awg_jmin"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmin)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_jmin"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmin)
			isAmnezia = true
		}

		if val, exists := oMap["awg_jmax"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmax)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_jmax"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.Jmax)
			isAmnezia = true
		}

		if val, exists := oMap["awg_s1"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S1)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_s1"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S1)
			isAmnezia = true
		}

		if val, exists := oMap["awg_s2"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S2)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_s2"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S2)
			isAmnezia = true
		}

		if val, exists := oMap["awg_s3"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S3)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_s3"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S3)
			isAmnezia = true
		}

		if val, exists := oMap["awg_s4"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S4)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_s4"]; exists {
			fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &cfg.S4)
			isAmnezia = true
		}

		if val, exists := oMap["awg_h1"]; exists {
			cfg.H1 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_h1"]; exists {
			cfg.H1 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}

		if val, exists := oMap["awg_h2"]; exists {
			cfg.H2 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_h2"]; exists {
			cfg.H2 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}

		if val, exists := oMap["awg_h3"]; exists {
			cfg.H3 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_h3"]; exists {
			cfg.H3 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}

		if val, exists := oMap["awg_h4"]; exists {
			cfg.H4 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_h4"]; exists {
			cfg.H4 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}

		if val, exists := oMap["awg_i1"]; exists {
			cfg.I1 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_i1"]; exists {
			cfg.I1 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}
		if val, exists := oMap["awg_i2"]; exists {
			cfg.I2 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_i2"]; exists {
			cfg.I2 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}
		if val, exists := oMap["awg_i3"]; exists {
			cfg.I3 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_i3"]; exists {
			cfg.I3 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}
		if val, exists := oMap["awg_i4"]; exists {
			cfg.I4 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_i4"]; exists {
			cfg.I4 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}
		if val, exists := oMap["awg_i5"]; exists {
			cfg.I5 = fmt.Sprintf("%v", val)
			isAmnezia = true
		} else if val, exists := oMap["amnezia_i5"]; exists {
			cfg.I5 = fmt.Sprintf("%v", val)
			isAmnezia = true
		}

		if isAmnezia {
			cfg.Protocol = proxyconfig.ProtocolAmneziaWG
		}

		applySingBoxImportedFields(cfg, oMap)
		if err := cfg.Validate(); err == nil {
			configs = append(configs, cfg)
		}
	}

	// Resolve detours by linking DialerProxy tag to actual Detour pointer
	for _, cfg := range configs {
		if cfg.DialerProxy != "" {
			for _, other := range configs {
				if other.Name == cfg.DialerProxy {
					cfg.Detour = other
					break
				}
			}
		}
	}

	return configs, nil
}

func stringFromMap(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok && v != nil {
			return strings.TrimSpace(fmt.Sprintf("%v", v))
		}
	}
	return ""
}

func intFromMap(m map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if v, ok := m[key]; ok && v != nil {
			var out int
			if _, err := fmt.Sscanf(fmt.Sprintf("%v", v), "%d", &out); err == nil {
				return out
			}
		}
	}
	return 0
}

func boolFromMap(m map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			switch typed := v.(type) {
			case bool:
				return typed
			case string:
				return strings.EqualFold(typed, "true") || typed == "1"
			}
		}
	}
	return false
}

func stringSliceFromAny(v interface{}) []string {
	switch typed := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := strings.TrimSpace(fmt.Sprintf("%v", item)); value != "" {
				out = append(out, value)
			}
		}
		return out
	case []string:
		return append([]string(nil), typed...)
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	default:
		return nil
	}
}

func mapFromAny(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func parseMbps(raw string) int {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "mbps"))
	var out int
	_, _ = fmt.Sscanf(raw, "%d", &out)
	return out
}

func applyClashImportedFields(cfg *proxyconfig.ProxyConfig, m map[string]interface{}) {
	if cfg.UUID == "" {
		cfg.UUID = stringFromMap(m, "username")
	}
	if cfg.Security == "" {
		cfg.Security = stringFromMap(m, "cipher")
	}
	if cfg.Flow == "" {
		cfg.Flow = stringFromMap(m, "flow")
	}
	cfg.TLS = cfg.TLS || boolFromMap(m, "tls")
	cfg.SkipCertVerify = cfg.SkipCertVerify || boolFromMap(m, "skip-cert-verify", "skip_cert_verify")
	if cfg.SNI == "" {
		cfg.SNI = stringFromMap(m, "servername", "sni")
	}
	if cfg.Fingerprint == "" {
		cfg.Fingerprint = stringFromMap(m, "client-fingerprint", "client_fingerprint")
	}
	if v, ok := m["alpn"]; ok {
		cfg.ALPN = stringSliceFromAny(v)
	}
	if reality := mapFromAny(m["reality-opts"]); reality != nil {
		cfg.Security = "reality"
		cfg.TLS = true
		cfg.PublicKey = stringFromMap(reality, "public-key", "public_key")
		cfg.ShortID = stringFromMap(reality, "short-id", "short_id")
	}
	if network := strings.ToLower(stringFromMap(m, "network")); network != "" {
		cfg.Transport = network
	}
	if ws := mapFromAny(m["ws-opts"]); ws != nil {
		cfg.Transport = "ws"
		cfg.Path = stringFromMap(ws, "path")
		if headers := mapFromAny(ws["headers"]); headers != nil {
			cfg.Host = stringFromMap(headers, "Host", "host")
		}
	}
	if grpc := mapFromAny(m["grpc-opts"]); grpc != nil {
		cfg.Transport = "grpc"
		cfg.ServiceName = stringFromMap(grpc, "grpc-service-name", "service-name", "service_name")
	}
	if upgrade := mapFromAny(m["http-upgrade-opts"]); upgrade != nil {
		cfg.Transport = "httpupgrade"
		cfg.Path = stringFromMap(upgrade, "path")
		cfg.Host = stringFromMap(upgrade, "host")
	}
	if raw, ok := m["ports"]; ok && cfg.Protocol == proxyconfig.ProtocolHysteria2 {
		cfg.Hysteria2PortHopping = strings.TrimSpace(fmt.Sprintf("%v", raw))
	}
	if cfg.Protocol == proxyconfig.ProtocolHysteria2 {
		cfg.Obfuscation = stringFromMap(m, "obfs-password", "obfs_password")
		cfg.UpMbps = parseMbps(stringFromMap(m, "up"))
		cfg.DownMbps = parseMbps(stringFromMap(m, "down"))
	}
	if cfg.Protocol == proxyconfig.ProtocolTUIC {
		cfg.CongestionControl = stringFromMap(m, "congestion-controller", "congestion_control")
		cfg.UDPRelayMode = stringFromMap(m, "udp-relay-mode", "udp_relay_mode")
	}
	if cfg.Protocol == proxyconfig.ProtocolAnyTLS {
		cfg.AnyTLSIdleSessionCheckInterval = stringFromMap(m, "idle-session-check-interval")
		cfg.AnyTLSIdleSessionTimeout = stringFromMap(m, "idle-session-timeout")
		cfg.MinIdleSessions = intFromMap(m, "min-idle-session")
		cfg.TLS = true
	}
}

func applySingBoxImportedFields(cfg *proxyconfig.ProxyConfig, m map[string]interface{}) {
	if cfg.UUID == "" {
		cfg.UUID = stringFromMap(m, "username")
	}
	if cfg.Security == "" {
		cfg.Security = stringFromMap(m, "security")
	}
	cfg.AlterID = intFromMap(m, "alter_id")
	if cfg.Flow == "" {
		cfg.Flow = stringFromMap(m, "flow")
	}
	if cfg.Protocol == proxyconfig.ProtocolNaive && cfg.UUID == "" {
		cfg.UUID = stringFromMap(m, "username")
	}
	if cfg.Protocol == proxyconfig.ProtocolTUIC {
		cfg.CongestionControl = stringFromMap(m, "congestion_control")
		cfg.UDPRelayMode = stringFromMap(m, "udp_relay_mode")
	}
	if cfg.Protocol == proxyconfig.ProtocolAnyTLS {
		cfg.AnyTLSIdleSessionCheckInterval = stringFromMap(m, "idle_session_check_interval")
		cfg.AnyTLSIdleSessionTimeout = stringFromMap(m, "idle_session_timeout")
		cfg.MinIdleSessions = intFromMap(m, "min_idle_session", "min_idle_sessions")
		cfg.TLS = true
	}
	if cfg.Protocol == proxyconfig.ProtocolJuicity {
		cfg.CongestionControl = stringFromMap(m, "congestion_control")
		cfg.PinnedCertChainSHA256 = stringFromMap(m, "pinned_certchain_sha256")
	}
	if cfg.Protocol == proxyconfig.ProtocolDNSTT {
		cfg.Address = stringFromMap(m, "domain")
		cfg.Port = 53
		cfg.PublicKey = stringFromMap(m, "publicKey", "public_key")
		if v, ok := m["resolvers"]; ok {
			cfg.Resolvers = stringSliceFromAny(v)
		}
		cfg.TunnelPerResolver = intFromMap(m, "tunnel_per_resolver")
		cfg.UDPOverTCP = boolFromMap(m, "udp_over_tcp")
	}
	if cfg.Protocol == proxyconfig.ProtocolHysteria2 {
		if v, ok := m["server_ports"]; ok {
			parts := stringSliceFromAny(v)
			cfg.Hysteria2PortHopping = strings.Join(parts, ",")
		}
		if obfs := mapFromAny(m["obfs"]); obfs != nil {
			cfg.Obfuscation = stringFromMap(obfs, "password")
		}
		if bw := mapFromAny(m["bandwidth"]); bw != nil {
			cfg.UpMbps = parseMbps(stringFromMap(bw, "up"))
			cfg.DownMbps = parseMbps(stringFromMap(bw, "down"))
		}
	}
	if tls := mapFromAny(m["tls"]); tls != nil {
		cfg.TLS = boolFromMap(tls, "enabled") || cfg.Protocol == proxyconfig.ProtocolAnyTLS
		cfg.SkipCertVerify = boolFromMap(tls, "insecure")
		cfg.SNI = stringFromMap(tls, "server_name")
		if v, ok := tls["alpn"]; ok {
			cfg.ALPN = stringSliceFromAny(v)
		}
		if reality := mapFromAny(tls["reality"]); reality != nil && boolFromMap(reality, "enabled") {
			cfg.Security = "reality"
			cfg.PublicKey = stringFromMap(reality, "public_key")
			cfg.ShortID = stringFromMap(reality, "short_id")
		}
	}
	if transport := mapFromAny(m["transport"]); transport != nil {
		typeName := strings.ToLower(stringFromMap(transport, "type"))
		cfg.Transport = typeName
		switch typeName {
		case "ws", "websocket":
			cfg.Transport = "ws"
			cfg.Path = stringFromMap(transport, "path")
			if headers := mapFromAny(transport["headers"]); headers != nil {
				cfg.Host = stringFromMap(headers, "Host", "host")
			}
		case "grpc":
			cfg.ServiceName = stringFromMap(transport, "service_name")
		case "httpupgrade":
			cfg.Path = stringFromMap(transport, "path")
			cfg.Host = stringFromMap(transport, "host")
		}
	}
	if mux := mapFromAny(m["multiplex"]); mux != nil {
		cfg.SmuxEnabled = boolFromMap(mux, "enabled")
		cfg.SmuxConcurrency = intFromMap(mux, "max_connections")
	}
}

// DecodeBase64Mixed attempts to decode a base64 string using both standard
// and URL-safe alphabets, with and without padding. Returns the decoded
// string or an error if all attempts fail.
func decodeBase64Mixed(input string) (string, error) {
	input = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, input)

	dec, err := base64.StdEncoding.DecodeString(input)
	if err == nil {
		return string(dec), nil
	}

	dec, err = base64.URLEncoding.DecodeString(input)
	if err == nil {
		return string(dec), nil
	}

	for i := 1; i <= 3; i++ {
		padded := input + strings.Repeat("=", i)
		dec, err = base64.StdEncoding.DecodeString(padded)
		if err == nil {
			return string(dec), nil
		}
		dec, err = base64.URLEncoding.DecodeString(padded)
		if err == nil {
			return string(dec), nil
		}
	}

	dec, err = base64.RawStdEncoding.DecodeString(input)
	if err == nil {
		return string(dec), nil
	}

	dec, err = base64.RawURLEncoding.DecodeString(input)
	if err == nil {
		return string(dec), nil
	}

	return "", fmt.Errorf("failed to decode base64 mixed string")
}

// parseReservedField decodes robust reserved byte arrays from float64, integer, base64 strings, or lists.
func parseReservedField(val interface{}) []int {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case []interface{}:
		var res []int
		for _, item := range v {
			var intVal int
			if _, err := fmt.Sscanf(fmt.Sprintf("%v", item), "%d", &intVal); err == nil {
				res = append(res, intVal)
			}
		}
		return res
	case string:
		trimmed := strings.TrimSpace(v)
		if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) > 0 {
			res := make([]int, len(decoded))
			for i, b := range decoded {
				res[i] = int(b)
			}
			return res
		}
		var res []int
		parts := strings.Split(trimmed, ",")
		for _, p := range parts {
			var intVal int
			if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &intVal); err == nil {
				res = append(res, intVal)
			}
		}
		return res
	case float64:
		return []int{int(v)}
	case int:
		return []int{v}
	}
	return nil
}
