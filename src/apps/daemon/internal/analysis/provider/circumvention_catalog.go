package provider

// CircumventionCapability is a target-native operator catalog derived from
// cross-project anti-censorship/privacy/Tor taxonomies. It describes LumiNet's
// actual integration level rather than mirroring external project lists.
type CircumventionCapability struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Category        string   `json:"category"`
	Integration     string   `json:"integration"` // native, external-engine, reference
	OperatorSurface string   `json:"operator_surface,omitempty"`
	Description     string   `json:"description"`
	Tags            []string `json:"tags,omitempty"`
}

// CircumventionCatalog returns a defensive copy sorted by product grouping.
func CircumventionCatalog() []CircumventionCapability {
	out := make([]CircumventionCapability, len(circumventionCatalog))
	copy(out, circumventionCatalog)
	for i := range out {
		out[i].Tags = append([]string(nil), out[i].Tags...)
	}
	return out
}

var circumventionCatalog = []CircumventionCapability{
	{ID: "tor", Name: "Tor", Category: "anonymity", Integration: "external-engine", OperatorSurface: "Operations / Tor identity & onion tools", Description: "Long-lived Tor SOCKS engine with SAFECOOKIE circuit rotation, bridge configuration, and onion reachability diagnostics.", Tags: []string{"socks5", "onion", "bridges"}},
	{ID: "psiphon", Name: "Psiphon", Category: "circumvention", Integration: "external-engine", OperatorSurface: "Operations / Runtime engines", Description: "Long-lived Psiphon engine integrated through runtimecore.", Tags: []string{"proxy", "tunnel"}},
	{ID: "sstp", Name: "SSTP", Category: "vpn", Integration: "external-engine", OperatorSurface: "Operations / SSTP", Description: "System-tunnel engine with proxy, CA, certificate-warning and PPP option controls.", Tags: []string{"vpn", "ppp"}},
	{ID: "vpngate", Name: "VPN Gate", Category: "vpn-directory", Integration: "native", OperatorSurface: "Operations / VPN Gate discovery", Description: "Bounded public server discovery, ranking, filtering, and SSTP handoff.", Tags: []string{"sstp", "public-relay"}},
	{ID: "vless-xhttp", Name: "VLESS + XHTTP", Category: "proxy-transport", Integration: "native", OperatorSurface: "Profiles / Operations / Devcontainer", Description: "Canonical share parsing, Xray runtime configuration, and reviewable devcontainer generation for XHTTP modes.", Tags: []string{"xray", "xhttp", "vless"}},
	{ID: "hysteria2", Name: "Hysteria2", Category: "proxy-transport", Integration: "native", OperatorSurface: "Profiles", Description: "Canonical proxy grammar with obfuscation, ALPN, bandwidth, port-range and certificate-pin semantics split by core capability.", Tags: []string{"quic", "udp"}},
	{ID: "wireguard", Name: "WireGuard", Category: "vpn", Integration: "native", OperatorSurface: "Profiles", Description: "Canonical WireGuard profile support including pre-shared keys and target-core mapping.", Tags: []string{"udp", "vpn"}},
	{ID: "shadowsocks", Name: "Shadowsocks", Category: "proxy-transport", Integration: "native", OperatorSurface: "Profiles", Description: "Share/config parsing and runtime proxy support.", Tags: []string{"proxy"}},
	{ID: "trojan", Name: "Trojan", Category: "proxy-transport", Integration: "native", OperatorSurface: "Profiles", Description: "Canonical Trojan transport parsing including current XHTTP/TLS metadata.", Tags: []string{"tls", "proxy"}},
	{ID: "reality", Name: "REALITY", Category: "transport-security", Integration: "native", OperatorSurface: "Profiles", Description: "Xray REALITY metadata including public key, short ID and spiderX preservation.", Tags: []string{"xray", "tls-camouflage"}},
	{ID: "obfs4", Name: "obfs4", Category: "pluggable-transport", Integration: "external-engine", OperatorSurface: "Tor bridge configuration", Description: "Tor engine accepts bridge lines and an obfs4 transport executable when configured.", Tags: []string{"tor", "bridge"}},
	{ID: "snowflake", Name: "Snowflake", Category: "pluggable-transport", Integration: "reference", Description: "Recognized circumvention technique; no first-class LumiNet engine is currently promoted."},
	{ID: "meek", Name: "meek", Category: "pluggable-transport", Integration: "reference", Description: "Recognized domain-fronting transport; no first-class LumiNet engine is currently promoted."},
	{ID: "i2p", Name: "I2P", Category: "anonymity", Integration: "reference", Description: "Recognized anonymity network; no LumiNet runtime owner is currently promoted."},
	{ID: "ooni", Name: "OONI-style measurement", Category: "measurement", Integration: "reference", Description: "External censorship measurement concept; LumiNet currently provides its own bounded diagnostics rather than an OONI integration."},
}
