package sub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

// ConversionTarget identifies a deterministic, local-only export representation.
// Conversion never fetches remote data; callers must provide already parsed nodes.
type ConversionTarget string

const (
	ConversionURIList     ConversionTarget = "uri-list"
	ConversionBase64      ConversionTarget = "base64"
	ConversionLumiNetJSON ConversionTarget = "luminet-json"
	ConversionClashMeta   ConversionTarget = "clash-meta"
	ConversionSingBox     ConversionTarget = "sing-box"
)

const (
	maxConversionNodes       = 4096
	maxConversionOutputBytes = 16 << 20
)

type ConversionIssue struct {
	Index    int                       `json:"index"`
	Name     string                    `json:"name,omitempty"`
	Protocol proxyconfig.ProxyProtocol `json:"protocol,omitempty"`
	Severity string                    `json:"severity"`
	Code     string                    `json:"code"`
	Message  string                    `json:"message"`
}

type ConversionReport struct {
	SourceNodes  int               `json:"source_nodes"`
	EmittedNodes int               `json:"emitted_nodes"`
	Unsupported  int               `json:"unsupported"`
	Lossy        int               `json:"lossy"`
	Warnings     int               `json:"warnings"`
	Issues       []ConversionIssue `json:"issues,omitempty"`
}

type ConversionResult struct {
	Target         ConversionTarget `json:"target"`
	MIMEType       string           `json:"mime_type"`
	Content        string           `json:"content"`
	Report         ConversionReport `json:"report"`
	Transformation *TransformReport `json:"transformation,omitempty"`
	RoundTrip      *RoundTripReport `json:"round_trip,omitempty"`
}

var ErrStrictConversion = errors.New("strict conversion rejected incompatible nodes")

func SupportedConversionTargets() []ConversionTarget {
	return []ConversionTarget{ConversionURIList, ConversionBase64, ConversionLumiNetJSON, ConversionClashMeta, ConversionSingBox}
}

func ValidConversionTarget(target ConversionTarget) bool {
	for _, candidate := range SupportedConversionTargets() {
		if target == candidate {
			return true
		}
	}
	return false
}

// ConvertConfigs renders canonical LumiNet proxy nodes into target without
// silently dropping incompatibilities. In non-strict mode representable nodes
// are emitted and every omitted/lossy semantic is reported. Strict mode returns
// ErrStrictConversion whenever unsupported or lossy semantics are discovered.
func ConvertConfigs(configs []*proxyconfig.ProxyConfig, target ConversionTarget, strict bool) (ConversionResult, error) {
	result := ConversionResult{Target: target, Report: ConversionReport{SourceNodes: len(configs)}}
	if !ValidConversionTarget(target) {
		return result, fmt.Errorf("unsupported conversion target %q", target)
	}
	if len(configs) == 0 {
		return result, errors.New("no proxy nodes to convert")
	}
	if len(configs) > maxConversionNodes {
		return result, fmt.Errorf("conversion node count exceeds %d", maxConversionNodes)
	}

	names := uniqueConversionNames(configs)
	var err error
	switch target {
	case ConversionURIList, ConversionBase64:
		result.MIMEType = "text/plain; charset=utf-8"
		result.Content, result.Report, err = convertURIRepresentations(configs, names, target == ConversionBase64)
	case ConversionLumiNetJSON:
		result.MIMEType = "application/json"
		result.Content, result.Report, err = convertLumiNetJSON(configs)
	case ConversionClashMeta:
		result.MIMEType = "application/yaml; charset=utf-8"
		result.Content, result.Report, err = convertClashMeta(configs, names)
	case ConversionSingBox:
		result.MIMEType = "application/json"
		result.Content, result.Report, err = convertSingBox(configs, names)
	}
	result.Report.SourceNodes = len(configs)
	if err != nil {
		return result, err
	}
	sortConversionIssues(result.Report.Issues)
	if len(result.Content) > maxConversionOutputBytes {
		return result, fmt.Errorf("conversion output exceeds %d bytes", maxConversionOutputBytes)
	}
	if strict && (result.Report.Unsupported > 0 || result.Report.Lossy > 0) {
		return result, fmt.Errorf("%w: unsupported=%d lossy=%d", ErrStrictConversion, result.Report.Unsupported, result.Report.Lossy)
	}
	return result, nil
}

func uniqueConversionNames(configs []*proxyconfig.ProxyConfig) []string {
	out := make([]string, len(configs))
	seen := make(map[string]int, len(configs))
	for i, cfg := range configs {
		base := "node-" + strconv.Itoa(i+1)
		if cfg != nil && strings.TrimSpace(cfg.Name) != "" {
			base = strings.TrimSpace(cfg.Name)
		}
		if len(base) > 128 {
			base = base[:128]
		}
		seen[base]++
		if seen[base] == 1 {
			out[i] = base
		} else {
			out[i] = fmt.Sprintf("%s (%d)", base, seen[base])
		}
	}
	return out
}

func newIssue(index int, cfg *proxyconfig.ProxyConfig, severity, code, message string) ConversionIssue {
	issue := ConversionIssue{Index: index + 1, Severity: severity, Code: code, Message: message}
	if cfg != nil {
		issue.Name = cfg.Name
		issue.Protocol = cfg.Protocol
	}
	return issue
}

func addIssue(report *ConversionReport, issue ConversionIssue) {
	report.Issues = append(report.Issues, issue)
	switch issue.Severity {
	case "unsupported":
		report.Unsupported++
	case "lossy":
		report.Lossy++
	default:
		report.Warnings++
	}
}

func validNode(index int, cfg *proxyconfig.ProxyConfig, report *ConversionReport) bool {
	if cfg == nil {
		addIssue(report, newIssue(index, nil, "unsupported", "nil_node", "node is nil"))
		return false
	}
	if err := cfg.Validate(); err != nil {
		addIssue(report, newIssue(index, cfg, "unsupported", "invalid_node", err.Error()))
		return false
	}
	return true
}

func convertURIRepresentations(configs []*proxyconfig.ProxyConfig, names []string, encode bool) (string, ConversionReport, error) {
	report := ConversionReport{SourceNodes: len(configs)}
	lines := make([]string, 0, len(configs))
	for i, cfg := range configs {
		if !validNode(i, cfg, &report) {
			continue
		}
		copyCfg := *cfg
		copyCfg.Name = names[i]
		uri := strings.TrimSpace(copyCfg.ToURI())
		if uri == "" {
			addIssue(&report, newIssue(i, cfg, "unsupported", "share_link_unavailable", "canonical node has no share-link representation"))
			continue
		}
		lines = append(lines, uri)
		report.EmittedNodes++
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	if encode {
		content = base64.StdEncoding.EncodeToString([]byte(content))
	}
	return content, report, nil
}

func convertLumiNetJSON(configs []*proxyconfig.ProxyConfig) (string, ConversionReport, error) {
	report := ConversionReport{SourceNodes: len(configs)}
	nodes := make([]*proxyconfig.ProxyConfig, 0, len(configs))
	for i, cfg := range configs {
		if !validNode(i, cfg, &report) {
			continue
		}
		nodes = append(nodes, cfg)
		report.EmittedNodes++
	}
	bundle := struct {
		Schema string                     `json:"schema"`
		Nodes  []*proxyconfig.ProxyConfig `json:"nodes"`
	}{Schema: "luminet.proxy-bundle.v1", Nodes: nodes}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", report, err
	}
	return string(data) + "\n", report, nil
}

func convertClashMeta(configs []*proxyconfig.ProxyConfig, names []string) (string, ConversionReport, error) {
	report := ConversionReport{SourceNodes: len(configs)}
	proxies := make([]map[string]any, 0, len(configs))
	emittedNames := make([]string, 0, len(configs))
	for i, cfg := range configs {
		if !validNode(i, cfg, &report) {
			continue
		}
		proxy, issues := clashProxy(cfg, names[i], i)
		for _, issue := range issues {
			addIssue(&report, issue)
		}
		if proxy == nil {
			continue
		}
		proxies = append(proxies, proxy)
		emittedNames = append(emittedNames, names[i])
		report.EmittedNodes++
	}

	var b strings.Builder
	b.WriteString("# Generated by LumiNet compatibility conversion. JSON flow mappings are valid YAML and preserve escaping.\n")
	b.WriteString("proxies:\n")
	for _, proxy := range proxies {
		encoded, err := json.Marshal(proxy)
		if err != nil {
			return "", report, err
		}
		b.WriteString("  - ")
		b.Write(encoded)
		b.WriteByte('\n')
	}
	groups := []map[string]any{
		{"name": "Proxy", "type": "select", "proxies": append([]string{"Auto", "DIRECT"}, emittedNames...)},
		{"name": "Auto", "type": "url-test", "proxies": emittedNames, "url": "https://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50},
	}
	b.WriteString("proxy-groups:\n")
	for _, group := range groups {
		encoded, err := json.Marshal(group)
		if err != nil {
			return "", report, err
		}
		b.WriteString("  - ")
		b.Write(encoded)
		b.WriteByte('\n')
	}
	b.WriteString("rules:\n  - \"MATCH,Proxy\"\n")
	return b.String(), report, nil
}

func clashProxy(cfg *proxyconfig.ProxyConfig, name string, index int) (map[string]any, []ConversionIssue) {
	issues := clashCompatibilityIssues(cfg, index)
	for _, issue := range issues {
		if issue.Severity == "unsupported" {
			return nil, issues
		}
	}
	base := map[string]any{"name": name, "server": cfg.Address, "port": cfg.Port}
	switch cfg.Protocol {
	case proxyconfig.ProtocolVMess:
		base["type"] = "vmess"
		base["uuid"] = cfg.UUID
		base["alterId"] = cfg.AlterID
		base["cipher"] = valueOr(cfg.Security, "auto")
	case proxyconfig.ProtocolVLESS:
		base["type"] = "vless"
		base["uuid"] = cfg.UUID
		if cfg.Flow != "" {
			base["flow"] = cfg.Flow
		}
	case proxyconfig.ProtocolTrojan:
		base["type"] = "trojan"
		base["password"] = cfg.Password
	case proxyconfig.ProtocolShadowsocks:
		base["type"] = "ss"
		base["cipher"] = cfg.Method
		base["password"] = cfg.Password
		if cfg.Plugin != "" {
			base["plugin"] = cfg.Plugin
		}
		if cfg.PluginOpts != "" {
			base["plugin-opts"] = cfg.PluginOpts
		}
	case proxyconfig.ProtocolShadowsocksR:
		base["type"] = "ssr"
		base["cipher"] = cfg.Method
		base["password"] = cfg.Password
		base["protocol"] = cfg.Protocol_
		base["obfs"] = cfg.Obfs
		if cfg.ProtocolParam != "" {
			base["protocol-param"] = cfg.ProtocolParam
		}
		if cfg.ObfsParam != "" {
			base["obfs-param"] = cfg.ObfsParam
		}
	case proxyconfig.ProtocolSOCKS5:
		base["type"] = "socks5"
		if cfg.UUID != "" {
			base["username"] = cfg.UUID
		}
		if cfg.Password != "" {
			base["password"] = cfg.Password
		}
	case proxyconfig.ProtocolHTTP:
		base["type"] = "http"
		if cfg.UUID != "" {
			base["username"] = cfg.UUID
		}
		if cfg.Password != "" {
			base["password"] = cfg.Password
		}
	case proxyconfig.ProtocolHysteria2:
		base["type"] = "hysteria2"
		base["password"] = cfg.Password
		if cfg.Hysteria2PortHopping != "" {
			base["ports"] = cfg.Hysteria2PortHopping
		}
		if cfg.Obfuscation != "" {
			base["obfs"] = "salamander"
			base["obfs-password"] = cfg.Obfuscation
		}
		if cfg.UpMbps > 0 {
			base["up"] = fmt.Sprintf("%d Mbps", cfg.UpMbps)
		}
		if cfg.DownMbps > 0 {
			base["down"] = fmt.Sprintf("%d Mbps", cfg.DownMbps)
		}
	case proxyconfig.ProtocolTUIC:
		base["type"] = "tuic"
		base["uuid"] = cfg.UUID
		base["password"] = cfg.Password
		if cfg.CongestionControl != "" {
			base["congestion-controller"] = cfg.CongestionControl
		}
		if cfg.UDPRelayMode != "" {
			base["udp-relay-mode"] = cfg.UDPRelayMode
		}
	case proxyconfig.ProtocolAnyTLS:
		base["type"] = "anytls"
		base["password"] = cfg.Password
		if cfg.AnyTLSIdleSessionCheckInterval != "" {
			base["idle-session-check-interval"] = cfg.AnyTLSIdleSessionCheckInterval
		}
		if cfg.AnyTLSIdleSessionTimeout != "" {
			base["idle-session-timeout"] = cfg.AnyTLSIdleSessionTimeout
		}
		if cfg.MinIdleSessions > 0 {
			base["min-idle-session"] = cfg.MinIdleSessions
		}
	default:
		return nil, append(issues, newIssue(index, cfg, "unsupported", "clash_protocol", "protocol is not represented by the LumiNet Clash Meta exporter"))
	}
	applyClashTLSAndTransport(base, cfg)
	return base, issues
}

func clashCompatibilityIssues(cfg *proxyconfig.ProxyConfig, index int) []ConversionIssue {
	var issues []ConversionIssue
	if cfg.Detour != nil || cfg.DialerProxy != "" {
		issues = append(issues, newIssue(index, cfg, "unsupported", "detour_chain", "detour chains cannot be represented as one Clash proxy record"))
	}
	for code, present := range map[string]bool{
		"xray_final_mask": cfg.FinalMask != "", "xray_xhttp": cfg.XHTTPMode != "" || cfg.XHTTPExtra != "" || proxyconfig.CanonicalXHTTPTransport(cfg.Transport) == "xhttp",
		"xray_ech": cfg.ECHConfigList != "", "xray_cert_pin": cfg.PinnedPeerCertSHA256 != "", "xray_cert_name_policy": cfg.VerifyPeerCertByName != "",
		"xray_fragment":        cfg.FragmentPackets != "" || cfg.FragmentLength != "" || cfg.FragmentInterval != "",
		"wireguard_extensions": cfg.Protocol == proxyconfig.ProtocolAmneziaWG || cfg.WNoise != "" || cfg.WNoiseCount != "" || cfg.WPayloadSize != "" || cfg.WNoiseDelay != "" || cfg.Jc != 0 || cfg.Jmin != 0 || cfg.Jmax != 0 || cfg.H1 != "" || cfg.H2 != "" || cfg.H3 != "" || cfg.H4 != "",
	} {
		if present {
			issues = append(issues, newIssue(index, cfg, "unsupported", code, "target would lose target-specific transport or WireGuard extension semantics"))
		}
	}
	if cfg.SmuxEnabled || cfg.SmuxConcurrency != 0 {
		issues = append(issues, newIssue(index, cfg, "lossy", "smux", "SMux settings are not emitted by the Clash compatibility target"))
	}
	return issues
}

func applyClashTLSAndTransport(out map[string]any, cfg *proxyconfig.ProxyConfig) {
	if cfg.TLS || cfg.Security == "tls" || cfg.Security == "reality" {
		out["tls"] = true
		if cfg.SNI != "" {
			out["servername"] = cfg.SNI
		}
		if cfg.SkipCertVerify {
			out["skip-cert-verify"] = true
		}
		if cfg.Fingerprint != "" {
			out["client-fingerprint"] = cfg.Fingerprint
		}
		if cfg.Security == "reality" {
			out["reality-opts"] = map[string]any{"public-key": cfg.PublicKey, "short-id": cfg.ShortID}
		}
	}
	if len(cfg.ALPN) > 0 {
		out["alpn"] = append([]string(nil), cfg.ALPN...)
	}
	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	switch transport {
	case "", "tcp":
	case "ws", "websocket":
		out["network"] = "ws"
		ws := map[string]any{}
		if cfg.Path != "" {
			ws["path"] = cfg.Path
		}
		if cfg.Host != "" {
			ws["headers"] = map[string]string{"Host": cfg.Host}
		}
		if len(ws) > 0 {
			out["ws-opts"] = ws
		}
	case "grpc":
		out["network"] = "grpc"
		grpc := map[string]any{"grpc-service-name": cfg.ServiceName}
		if cfg.Authority != "" {
			grpc["grpc-authority"] = cfg.Authority
		}
		out["grpc-opts"] = grpc
	case "h2", "http":
		out["network"] = "h2"
		h2 := map[string]any{}
		if cfg.Path != "" {
			h2["path"] = cfg.Path
		}
		if cfg.Host != "" {
			h2["host"] = []string{cfg.Host}
		}
		out["h2-opts"] = h2
	case "httpupgrade":
		out["network"] = "httpupgrade"
		out["http-upgrade-opts"] = map[string]any{"path": cfg.Path, "host": cfg.Host}
	default:
		out["network"] = transport
	}
}

func convertSingBox(configs []*proxyconfig.ProxyConfig, names []string) (string, ConversionReport, error) {
	report := ConversionReport{SourceNodes: len(configs)}
	base := make([]map[string]any, len(configs))
	usable := make([]bool, len(configs))
	for i, cfg := range configs {
		if !validNode(i, cfg, &report) {
			continue
		}
		outbound, issues := singBoxOutbound(cfg, names[i], i)
		for _, issue := range issues {
			addIssue(&report, issue)
		}
		if outbound == nil {
			continue
		}
		base[i] = outbound
		usable[i] = true
	}

	next, detourIssues := resolveSingBoxDetours(configs, names, usable)
	for _, issue := range detourIssues {
		addIssue(&report, issue)
		if issue.Index > 0 && issue.Index <= len(usable) && issue.Severity == "unsupported" {
			usable[issue.Index-1] = false
		}
	}
	// A chain is only exportable when every referenced downstream outbound is
	// exportable. Propagate that requirement to ancestors so no emitted config
	// can contain a dangling dialer_proxy reference.
	changed := true
	for changed {
		changed = false
		for i, j := range next {
			if usable[i] && j >= 0 && !usable[j] {
				addIssue(&report, newIssue(i, configs[i], "unsupported", "detour_target_unavailable", "detour target cannot be emitted by the sing-box compatibility target"))
				usable[i] = false
				changed = true
			}
		}
	}

	outbounds := make([]any, 0, len(configs)+2)
	tags := make([]string, 0, len(configs))
	for i := range configs {
		if !usable[i] || base[i] == nil {
			continue
		}
		if next[i] >= 0 {
			base[i]["dialer_proxy"] = names[next[i]]
		}
		outbounds = append(outbounds, base[i])
		tags = append(tags, names[i])
		report.EmittedNodes++
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
	if len(tags) > 0 {
		selector := map[string]any{"type": "selector", "tag": "proxy", "outbounds": tags, "default": tags[0]}
		outbounds = append(outbounds, selector)
	}
	config := map[string]any{"outbounds": outbounds}
	if len(tags) > 0 {
		config["route"] = map[string]any{"final": "proxy"}
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", report, err
	}
	return string(data) + "\n", report, nil
}

const maxConversionDetourDepth = 16

// resolveSingBoxDetours maps only explicit references between top-level
// canonical nodes. This matches the canonical sing-box importer, which resolves
// outbound tags into Detour pointers after parsing. Embedded anonymous chains
// remain unsupported because promoting them would invent independent profile
// identity and make compatibility reports non-bijective.
func resolveSingBoxDetours(configs []*proxyconfig.ProxyConfig, names []string, usable []bool) ([]int, []ConversionIssue) {
	next := make([]int, len(configs))
	for i := range next {
		next[i] = -1
	}
	byPtr := make(map[*proxyconfig.ProxyConfig]int, len(configs))
	byName := make(map[string][]int, len(configs))
	for i, cfg := range configs {
		if cfg == nil {
			continue
		}
		byPtr[cfg] = i
		name := strings.TrimSpace(cfg.Name)
		if name != "" {
			byName[name] = append(byName[name], i)
		}
	}
	var issues []ConversionIssue
	for i, cfg := range configs {
		if cfg == nil || !usable[i] {
			continue
		}
		target := -1
		if cfg.Detour != nil {
			if j, ok := byPtr[cfg.Detour]; ok {
				target = j
			} else {
				issues = append(issues, newIssue(i, cfg, "unsupported", "embedded_detour_chain", "embedded detour is not a top-level canonical node and cannot receive a stable export tag"))
				continue
			}
		}
		if raw := strings.TrimSpace(cfg.DialerProxy); raw != "" {
			matches := byName[raw]
			if len(matches) == 0 {
				issues = append(issues, newIssue(i, cfg, "unsupported", "dangling_detour", "dialer proxy does not resolve to a top-level canonical node"))
				continue
			}
			if len(matches) > 1 {
				issues = append(issues, newIssue(i, cfg, "unsupported", "ambiguous_detour", "dialer proxy name matches multiple canonical nodes"))
				continue
			}
			if target >= 0 && target != matches[0] {
				issues = append(issues, newIssue(i, cfg, "unsupported", "contradictory_detour", "Detour pointer and dialer proxy name resolve to different nodes"))
				continue
			}
			target = matches[0]
		}
		if target >= 0 {
			next[i] = target
		}
	}

	// Validate cycles and bound graph depth. A cycle invalidates every root that
	// enters it; conversion must never emit a self-referential outbound graph.
	for root := range configs {
		if !usable[root] || next[root] < 0 {
			continue
		}
		seen := map[int]struct{}{root: {}}
		cur := root
		for depth := 0; next[cur] >= 0; depth++ {
			if depth >= maxConversionDetourDepth {
				issues = append(issues, newIssue(root, configs[root], "unsupported", "detour_depth", fmt.Sprintf("detour chain exceeds %d hops", maxConversionDetourDepth)))
				break
			}
			cur = next[cur]
			if _, exists := seen[cur]; exists {
				issues = append(issues, newIssue(root, configs[root], "unsupported", "detour_cycle", "detour graph contains a cycle"))
				break
			}
			seen[cur] = struct{}{}
		}
	}
	_ = names // names are supplied to keep resolver contract paired with exported tag ownership.
	return next, issues
}

func singBoxOutbound(cfg *proxyconfig.ProxyConfig, tag string, index int) (map[string]any, []ConversionIssue) {
	var issues []ConversionIssue
	if err := proxyconfig.ValidateSingBoxCompatibility(cfg); err != nil {
		return nil, []ConversionIssue{newIssue(index, cfg, "unsupported", "singbox_compatibility", err.Error())}
	}
	out := map[string]any{"tag": tag, "server": cfg.Address, "server_port": cfg.Port}
	switch cfg.Protocol {
	case proxyconfig.ProtocolVMess:
		out["type"] = "vmess"
		out["uuid"] = cfg.UUID
		out["alter_id"] = cfg.AlterID
		out["security"] = valueOr(cfg.Security, "auto")
	case proxyconfig.ProtocolVLESS:
		out["type"] = "vless"
		out["uuid"] = cfg.UUID
		if cfg.Flow != "" {
			out["flow"] = cfg.Flow
		}
	case proxyconfig.ProtocolTrojan:
		out["type"] = "trojan"
		out["password"] = cfg.Password
	case proxyconfig.ProtocolShadowsocks:
		out["type"] = "shadowsocks"
		out["method"] = cfg.Method
		out["password"] = cfg.Password
		if cfg.Plugin != "" {
			out["plugin"] = cfg.Plugin
		}
		if cfg.PluginOpts != "" {
			out["plugin_opts"] = cfg.PluginOpts
		}
	case proxyconfig.ProtocolSOCKS5:
		out["type"] = "socks"
		if cfg.UUID != "" {
			out["username"] = cfg.UUID
		}
		if cfg.Password != "" {
			out["password"] = cfg.Password
		}
	case proxyconfig.ProtocolHTTP:
		out["type"] = "http"
		if cfg.UUID != "" {
			out["username"] = cfg.UUID
		}
		if cfg.Password != "" {
			out["password"] = cfg.Password
		}
	case proxyconfig.ProtocolHysteria2:
		out["type"] = "hysteria2"
		out["password"] = cfg.Password
		if cfg.Hysteria2PortHopping != "" {
			ports, err := proxyconfig.ParseHysteria2PortHopping(cfg.Hysteria2PortHopping)
			if err != nil {
				return nil, []ConversionIssue{newIssue(index, cfg, "unsupported", "hysteria2_ports", err.Error())}
			}
			if len(ports) > 0 {
				out["server_ports"] = ports
			}
		}
		if cfg.Obfuscation != "" {
			out["obfs"] = map[string]any{"type": "salamander", "password": cfg.Obfuscation}
		}
		if cfg.UpMbps > 0 || cfg.DownMbps > 0 {
			out["bandwidth"] = map[string]any{"up": fmt.Sprintf("%d Mbps", cfg.UpMbps), "down": fmt.Sprintf("%d Mbps", cfg.DownMbps)}
		}
	case proxyconfig.ProtocolTUIC:
		out["type"] = "tuic"
		out["uuid"] = cfg.UUID
		out["password"] = cfg.Password
		if cfg.CongestionControl != "" {
			out["congestion_control"] = cfg.CongestionControl
		}
		if cfg.UDPRelayMode != "" {
			out["udp_relay_mode"] = cfg.UDPRelayMode
		}
	case proxyconfig.ProtocolNaive:
		if strings.TrimSpace(cfg.UUID) == "" {
			return nil, []ConversionIssue{newIssue(index, cfg, "unsupported", "naive_username", "Naive export requires an explicit username")}
		}
		out["type"] = "naive"
		out["username"] = cfg.UUID
		out["password"] = cfg.Password
	case proxyconfig.ProtocolWireGuard, proxyconfig.ProtocolAmneziaWG:
		out["type"] = "wireguard"
		out["local_address"] = append([]string(nil), cfg.LocalAddress...)
		out["private_key"] = cfg.PrivateKey
		out["peer_public_key"] = cfg.PublicKey
		if cfg.PreSharedKey != "" {
			out["pre_shared_key"] = cfg.PreSharedKey
		}
		if len(cfg.Reserved) > 0 {
			out["reserved"] = append([]int(nil), cfg.Reserved...)
		}
		if cfg.MTU > 0 {
			out["mtu"] = cfg.MTU
		}
		applySingBoxWireGuardExtensions(out, cfg)
	case proxyconfig.ProtocolAnyTLS:
		out["type"] = "anytls"
		out["password"] = cfg.Password
		if cfg.AnyTLSIdleSessionCheckInterval != "" {
			out["idle_session_check_interval"] = cfg.AnyTLSIdleSessionCheckInterval
		}
		if cfg.AnyTLSIdleSessionTimeout != "" {
			out["idle_session_timeout"] = cfg.AnyTLSIdleSessionTimeout
		}
		if cfg.MinIdleSessions > 0 {
			out["min_idle_session"] = cfg.MinIdleSessions
		}
	case proxyconfig.ProtocolJuicity:
		out["type"] = "juicity"
		out["uuid"] = cfg.UUID
		out["password"] = cfg.Password
		if cfg.CongestionControl != "" {
			out["congestion_control"] = cfg.CongestionControl
		}
		if cfg.PinnedCertChainSHA256 != "" {
			out["pinned_certchain_sha256"] = cfg.PinnedCertChainSHA256
		}
	case proxyconfig.ProtocolDNSTT:
		if strings.TrimSpace(cfg.PublicKey) == "" || len(cfg.Resolvers) == 0 {
			return nil, []ConversionIssue{newIssue(index, cfg, "unsupported", "dnstt_parameters", "DNSTT export requires a public key and at least one resolver")}
		}
		out["type"] = "dnstt"
		delete(out, "server")
		delete(out, "server_port")
		out["publicKey"] = cfg.PublicKey
		out["domain"] = cfg.Address
		out["resolvers"] = append([]string(nil), cfg.Resolvers...)
		out["tunnel_per_resolver"] = cfg.TunnelPerResolver
		out["udp_over_tcp"] = cfg.UDPOverTCP
	default:
		return nil, []ConversionIssue{newIssue(index, cfg, "unsupported", "singbox_protocol", "protocol is not represented by the LumiNet sing-box compatibility target")}
	}
	applySingBoxTLSAndTransport(out, cfg)
	if cfg.SmuxEnabled || cfg.SmuxConcurrency > 0 {
		multiplex := map[string]any{"enabled": cfg.SmuxEnabled}
		if cfg.SmuxConcurrency > 0 {
			multiplex["max_connections"] = cfg.SmuxConcurrency
		}
		out["multiplex"] = multiplex
	}
	return out, issues
}

func applySingBoxTLSAndTransport(out map[string]any, cfg *proxyconfig.ProxyConfig) {
	if cfg.Protocol != proxyconfig.ProtocolHysteria2 && (cfg.TLS || cfg.Security == "tls" || cfg.Security == "reality") {
		tls := map[string]any{"enabled": true, "insecure": cfg.SkipCertVerify}
		serverName := cfg.SNI
		if serverName == "" {
			serverName = cfg.Address
		}
		tls["server_name"] = serverName
		if len(cfg.ALPN) > 0 {
			tls["alpn"] = append([]string(nil), cfg.ALPN...)
		}
		if cfg.Security == "reality" {
			tls["reality"] = map[string]any{"enabled": true, "public_key": cfg.PublicKey, "short_id": cfg.ShortID}
		}
		out["tls"] = tls
	} else if cfg.Protocol == proxyconfig.ProtocolHysteria2 && (cfg.TLS || cfg.SNI != "" || len(cfg.ALPN) > 0 || cfg.SkipCertVerify) {
		tls := map[string]any{"enabled": true, "insecure": cfg.SkipCertVerify}
		if cfg.SNI != "" {
			tls["server_name"] = cfg.SNI
		}
		if len(cfg.ALPN) > 0 {
			tls["alpn"] = append([]string(nil), cfg.ALPN...)
		}
		out["tls"] = tls
	}
	transport := strings.ToLower(strings.TrimSpace(cfg.Transport))
	if transport == "" || transport == "tcp" || cfg.Protocol == proxyconfig.ProtocolHysteria2 {
		return
	}
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
		if cfg.ServiceName != "" {
			tr["service_name"] = cfg.ServiceName
		}
	case "httpupgrade":
		if cfg.Path != "" {
			tr["path"] = cfg.Path
		}
		if cfg.Host != "" {
			tr["host"] = cfg.Host
		}
	}
	out["transport"] = tr
}

func applySingBoxWireGuardExtensions(out map[string]any, cfg *proxyconfig.ProxyConfig) {
	pairs := []struct {
		key string
		val any
		set bool
	}{
		{"fake_packets", cfg.FakePackets, cfg.FakePackets != ""}, {"fake_packets_size", cfg.FakePacketsSize, cfg.FakePacketsSize != ""},
		{"fake_packets_delay", cfg.FakePacketsDelay, cfg.FakePacketsDelay != ""}, {"fake_packets_mode", cfg.FakePacketsMode, cfg.FakePacketsMode != ""},
		{"awg_jc", cfg.Jc, cfg.Jc > 0}, {"awg_jmin", cfg.Jmin, cfg.Jmin > 0}, {"awg_jmax", cfg.Jmax, cfg.Jmax > 0},
		{"awg_s1", cfg.S1, cfg.S1 > 0}, {"awg_s2", cfg.S2, cfg.S2 > 0}, {"awg_s3", cfg.S3, cfg.S3 > 0}, {"awg_s4", cfg.S4, cfg.S4 > 0},
		{"awg_h1", cfg.H1, cfg.H1 != ""}, {"awg_h2", cfg.H2, cfg.H2 != ""}, {"awg_h3", cfg.H3, cfg.H3 != ""}, {"awg_h4", cfg.H4, cfg.H4 != ""},
		{"awg_i1", cfg.I1, cfg.I1 != ""}, {"awg_i2", cfg.I2, cfg.I2 != ""}, {"awg_i3", cfg.I3, cfg.I3 != ""}, {"awg_i4", cfg.I4, cfg.I4 != ""}, {"awg_i5", cfg.I5, cfg.I5 != ""},
	}
	for _, pair := range pairs {
		if pair.set {
			out[pair.key] = pair.val
		}
	}
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// sortConversionIssues makes report ordering independent of map iteration and
// therefore suitable for stable UI rendering and evidence snapshots.
func sortConversionIssues(issues []ConversionIssue) {
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Index != issues[j].Index {
			return issues[i].Index < issues[j].Index
		}
		if issues[i].Severity != issues[j].Severity {
			return issues[i].Severity < issues[j].Severity
		}
		return issues[i].Code < issues[j].Code
	})
}
