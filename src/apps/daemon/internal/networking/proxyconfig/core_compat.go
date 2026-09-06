package proxyconfig

import (
	"fmt"
	"strings"
)

// ExternalCoreCompatibility is a pure, credential-free description of which
// maintained external core builders can represent a parsed node without
// silently dropping semantics. It does not inspect installed binaries or
// start a process.
type ExternalCoreCompatibility struct {
	Activatable bool     `json:"activatable"`
	Cores       []string `json:"cores,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

func singBoxSupportsProtocol(protocol ProxyProtocol) bool {
	switch protocol {
	case ProtocolVMess, ProtocolVLESS, ProtocolTrojan, ProtocolShadowsocks, ProtocolSOCKS5, ProtocolHTTP,
		ProtocolHysteria2, ProtocolTUIC, ProtocolNaive, ProtocolWireGuard, ProtocolAmneziaWG, ProtocolDNSTT,
		ProtocolAnyTLS, ProtocolJuicity:
		return true
	default:
		return false
	}
}

func xraySupportsProtocol(protocol ProxyProtocol) bool {
	switch protocol {
	case ProtocolVMess, ProtocolVLESS, ProtocolTrojan, ProtocolShadowsocks, ProtocolSOCKS5, ProtocolHTTP,
		ProtocolHysteria2, ProtocolWireGuard, ProtocolAmneziaWG, ProtocolDNSTT, ProtocolAnyTLS, ProtocolJuicity:
		return true
	default:
		return false
	}
}

func validateShadowsocksPluginFields(p *ProxyConfig) error {
	plugin := strings.TrimSpace(p.Plugin)
	opts := strings.TrimSpace(p.PluginOpts)
	if strings.ContainsRune(plugin, '\x00') || strings.ContainsRune(opts, '\x00') {
		return fmt.Errorf("Shadowsocks plugin fields must not contain NUL")
	}
	if len(plugin) > 64 || len(opts) > 2048 {
		return fmt.Errorf("Shadowsocks plugin fields exceed bounded lengths")
	}
	if opts != "" && plugin == "" {
		return fmt.Errorf("Shadowsocks plugin_opts requires plugin")
	}
	return nil
}

// ValidateSingBoxCompatibility rejects fields that sing-box cannot represent
// instead of silently dropping share-link semantics.
func ValidateSingBoxCompatibility(p *ProxyConfig) error {
	if p == nil {
		return fmt.Errorf("proxy config is required")
	}
	if !singBoxSupportsProtocol(p.Protocol) {
		return fmt.Errorf("protocol %q is unsupported by sing-box outbound", p.Protocol)
	}
	if CanonicalXHTTPTransport(p.Transport) == "xhttp" {
		return fmt.Errorf("xhttp transport is owned by Xray and is unsupported by sing-box")
	}
	if p.FinalMask != "" || p.CipherSuites != "" || p.ECHConfigList != "" || p.VerifyPeerCertByName != "" || p.PinnedPeerCertSHA256 != "" || p.SpiderX != "" {
		return fmt.Errorf("configuration contains Xray-specific TLS/transport fields unsupported by sing-box")
	}
	if p.Protocol == ProtocolShadowsocks {
		if err := validateShadowsocksPluginFields(p); err != nil {
			return err
		}
		if p.Prefix != "" {
			return fmt.Errorf("Shadowsocks packet prefix is unsupported by sing-box outbound")
		}
		switch strings.TrimSpace(p.Plugin) {
		case "", "obfs-local", "v2ray-plugin":
		default:
			return fmt.Errorf("unsupported sing-box Shadowsocks SIP003 plugin %q", p.Plugin)
		}
	}
	return nil
}

// ValidateXrayCompatibility rejects Shadowsocks extension fields that Xray's
// outbound contract cannot represent. This keeps parsed plugin/prefix intent
// from being silently discarded when Xray is selected.
func ValidateXrayCompatibility(p *ProxyConfig) error {
	if p == nil {
		return fmt.Errorf("proxy config is required")
	}
	if !xraySupportsProtocol(p.Protocol) {
		return fmt.Errorf("protocol %q is unsupported by Xray outbound", p.Protocol)
	}
	if p.Protocol != ProtocolShadowsocks {
		return nil
	}
	if err := validateShadowsocksPluginFields(p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Plugin) != "" || strings.TrimSpace(p.PluginOpts) != "" {
		return fmt.Errorf("Shadowsocks SIP003 plugins are unsupported by Xray outbound")
	}
	if p.Prefix != "" {
		return fmt.Errorf("Shadowsocks packet prefix is unsupported by Xray outbound")
	}
	return nil
}

// EvaluateExternalCoreCompatibility evaluates the same fail-closed builders
// used by subscription activation, but performs no binary discovery, process
// launch, filesystem mutation, or network I/O. A node is activatable only when
// at least one maintained external core can represent all of its parsed intent.
func EvaluateExternalCoreCompatibility(p *ProxyConfig) ExternalCoreCompatibility {
	if p == nil {
		return ExternalCoreCompatibility{Reason: "proxy config is required"}
	}
	cores := make([]string, 0, 2)
	reasons := make([]string, 0, 2)
	if err := ValidateSingBoxCompatibility(p); err == nil {
		cores = append(cores, "sing-box")
	} else {
		reasons = append(reasons, "sing-box: "+err.Error())
	}
	if err := ValidateXrayCompatibility(p); err == nil {
		cores = append(cores, "xray")
	} else {
		reasons = append(reasons, "xray: "+err.Error())
	}
	if len(cores) > 0 {
		return ExternalCoreCompatibility{Activatable: true, Cores: cores}
	}
	return ExternalCoreCompatibility{Reason: strings.Join(reasons, "; ")}
}
