package proxy

// v2rayN-derived helpers for V2ray/Xray-core and Sing-box configuration.
// Source: v2rayN-master/v2rayN/ServiceLib/
//   - Global.cs            → protocol maps, constants, PredefinedHosts, fragment defaults
//   - V2rayOutboundService → ApplyOutboundFragment/ApplyFinalFragment/BuildFragmentsMasks
//   - SingboxRoutingService → tls_record_fragment route-options rule
//   - CertPemManager       → ParsePemChain, TrustedCAThumbprints, CA-pinning validation
//   - Utils.cs             → ParseUrl, IsPrivateNetwork, GetSystemHosts logic
//
// All of these translate to Go data structures and utilities used by the
// LumiNet server to generate V2ray/Xray/Sing-box config JSON payloads.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// V2ray / Xray Finalmask Fragment Config
// Source: V2rayOutboundService.BuildFragmentsMasks(), ApplyOutboundFragment(),
//         ApplyFinalFragment()
// ---------------------------------------------------------------------------

// V2rayFinalmaskConfig holds the Finalmask JSON section injected into an
// outbound's streamSettings to enable TCP fragmentation and UDP noise.
// Exact field names match Xray-core's Finalmask JSON spec.
type V2rayFinalmaskConfig struct {
	TCP []V2rayMask `json:"tcp,omitempty"`
	UDP []V2rayMask `json:"udp,omitempty"`
}

// V2rayMask is one entry in a Finalmask tcp/udp array.
type V2rayMask struct {
	// Type is "fragment" for TCP fragmentation or "noise" for UDP noise injection.
	Type     string             `json:"type"`
	Settings *V2rayMaskSettings `json:"settings,omitempty"`
}

// V2rayMaskSettings contains the per-mask parameters.
type V2rayMaskSettings struct {
	// Packets selects which packets are fragmented: "tlshello" or "1-3" range.
	Packets string `json:"packets,omitempty"`
	// Length is the byte-length range for each fragment: e.g. "50-100".
	Length string `json:"length,omitempty"`
	// Delay is the inter-fragment delay range in ms: e.g. "10-20".
	Delay string `json:"delay,omitempty"`
	// Value is used for mkcp-legacy seed.
	Value string `json:"value,omitempty"`
	// Password is used by the "salamander" obfuscation mask.
	Password string `json:"password,omitempty"`
}

// DefaultV2rayFragmentMask returns the standard fragment mask config that
// v2rayN injects for TLS outbounds.
// Defaults: packets="tlshello", length="50-100", delay="10-20".
// Source: ConfigHandler.LoadConfig() Fragment4RayItem defaults,
//
//	V2rayOutboundService.BuildFragmentsMasks().
func DefaultV2rayFragmentMask() V2rayMask {
	return V2rayMask{
		Type: "fragment",
		Settings: &V2rayMaskSettings{
			Packets: "tlshello",
			Length:  "50-100",
			Delay:   "10-20",
		},
	}
}

// DefaultV2rayNoiseMask returns the standard UDP noise mask that v2rayN
// injects alongside the fragment mask.
// Source: V2rayOutboundService.BuildFragmentsMasks()
func DefaultV2rayNoiseMask() V2rayMask {
	return V2rayMask{
		Type: "noise",
		Settings: &V2rayMaskSettings{
			Length: "10-20",
			Delay:  "10-16",
		},
	}
}

// NewV2rayFragmentFinalmask builds the full Finalmask config (tcp+udp) with
// configurable fragment parameters.
//
//	packets:  "tlshello" (TLS ClientHello only) or "1-3" (first N packets)
//	length:   byte range e.g. "50-100"
//	delay:    ms range e.g. "10-20"
func NewV2rayFragmentFinalmask(packets, length, delay string) V2rayFinalmaskConfig {
	if packets == "" {
		packets = "tlshello"
	}
	if length == "" {
		length = "50-100"
	}
	if delay == "" {
		delay = "10-20"
	}
	return V2rayFinalmaskConfig{
		TCP: []V2rayMask{{
			Type: "fragment",
			Settings: &V2rayMaskSettings{
				Packets: packets,
				Length:  length,
				Delay:   delay,
			},
		}},
		UDP: []V2rayMask{{
			Type: "noise",
			Settings: &V2rayMaskSettings{
				Length: "10-20",
				Delay:  "10-16",
			},
		}},
	}
}

// ---------------------------------------------------------------------------
// Sing-box TLS Record Fragment Routing Rule
// Source: SingboxRoutingService.GenRouting(), EnableFinalFragment check
// ---------------------------------------------------------------------------

// SingboxTLSFragmentRouteRule returns the sing-box route rule that enables
// TLS record fragmentation for all TLS protocol traffic (v1.11+ only).
// Insert this into route.rules before other rules when EnableFinalFragment=true.
//
// Format: {"protocol":["tls"],"action":"route-options","tls_record_fragment":true}
func SingboxTLSFragmentRouteRule() map[string]interface{} {
	return map[string]interface{}{
		"protocol":            []string{"tls"},
		"action":              "route-options",
		"tls_record_fragment": true,
	}
}

// ---------------------------------------------------------------------------
// Predefined DoH Hostname → IP Map
// Source: Global.cs PredefinedHosts
// Used to bootstrap DoH without relying on system DNS (anti-chicken-and-egg).
// ---------------------------------------------------------------------------

// PredefinedDoHHosts maps well-known DoH provider hostnames to their stable
// IP addresses (both IPv4 and IPv6). Use this to pre-seed a DoH resolver's
// offline DNS cache so it can reach the DoH server without resolving first.
var PredefinedDoHHosts = map[string][]string{
	"dns.google":                       {"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"},
	"dns.alidns.com":                   {"223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"},
	"one.one.one.one":                  {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"},
	"1dot1dot1dot1.cloudflare-dns.com": {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"},
	"cloudflare-dns.com":               {"104.16.249.249", "104.16.248.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"},
	"dns.cloudflare.com":               {"162.159.61.8", "172.64.41.8", "2a06:98c1:52::8", "2803:f800:53::8"},
	"dot.pub":                          {"1.12.12.12", "120.53.53.53"},
	"doh.pub":                          {"1.12.12.12", "120.53.53.53"},
	"dns.quad9.net":                    {"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"},
	"dns.yandex.net":                   {"77.88.8.8", "77.88.8.1", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"},
	"dns.sb":                           {"45.11.45.11", "185.222.222.222", "2a09::", "2a11::"},
	"dns.umbrella.com":                 {"208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53"},
	"engage.cloudflareclient.com":      {"162.159.192.1", "2606:4700:d0::a29f:c001"},
}

// ResolveDoHHostIP returns the first IPv4 address for a given DoH hostname
// from the predefined table. Returns "" if not found.
func ResolveDoHHostIP(hostname string) string {
	if ips, ok := PredefinedDoHHosts[strings.ToLower(hostname)]; ok {
		for _, ip := range ips {
			if net.ParseIP(ip) != nil && !strings.Contains(ip, ":") {
				return ip
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// V2ray Protocol Constants
// Source: Global.cs ProtocolShares, ProtocolTypes, Flows, Networks, Fingerprints
// ---------------------------------------------------------------------------

// V2rayProtocolSchemes maps protocol types to their URI scheme prefixes.
var V2rayProtocolSchemes = map[string]string{
	"vmess":     "vmess://",
	"ss":        "ss://",
	"socks":     "socks://",
	"vless":     "vless://",
	"trojan":    "trojan://",
	"hysteria2": "hysteria2://",
	"tuic":      "tuic://",
	"wireguard": "wireguard://",
	"anytls":    "anytls://",
	"naive":     "naive://",
}

// VLESSFlows are valid xtls-rprx-vision flow values for VLESS.
// Source: Global.cs Flows
var VLESSFlows = []string{
	"",
	"xtls-rprx-vision",
	"xtls-rprx-vision-udp443",
}

// TransportNetworks lists supported V2ray/Xray transport network types.
// Source: Global.cs Networks
var TransportNetworks = []string{
	"raw",
	"xhttp",
	"kcp",
	"grpc",
	"ws",
	"httpupgrade",
}

// XhttpModes lists the valid xhttp transport modes.
// Source: Global.cs XhttpMode
var XhttpModes = []string{
	"auto",
	"packet-up",
	"stream-up",
	"stream-one",
}

// TLSFingerprints lists the valid TLS fingerprint values for uTLS/Sing-box.
// Source: Global.cs Fingerprints
var TLSFingerprints = []string{
	"chrome", "firefox", "safari", "ios", "android",
	"edge", "360", "qq", "random", "randomized", "",
}

// ALPNValues lists the valid ALPN combinations.
// Source: Global.cs Alpns
var ALPNValues = []string{
	"h3", "h2", "http/1.1",
	"h3,h2", "h2,http/1.1", "h3,h2,http/1.1", "",
}

// VMessCiphers lists the valid VMess security (cipher) values.
// Source: Global.cs VmessSecurities
var VMessCiphers = []string{
	"aes-128-gcm", "chacha20-poly1305", "auto", "none", "zero",
}

// ShadowsocksCiphers lists valid Shadowsocks methods supported by Xray.
// Source: Global.cs SsSecuritiesInXray
var ShadowsocksCiphers = []string{
	"aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
	"xchacha20-poly1305", "xchacha20-ietf-poly1305", "none", "plain",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}

// Hysteria2DefaultHopIntervalSec is the default Hysteria2 UDP hop interval.
// Source: Global.cs Hysteria2DefaultHopInt = 30
const Hysteria2DefaultHopIntervalSec = 30

// TunMTUs are the valid MTU options for TUN mode.
// Source: Global.cs TunMtus
var TunMTUs = []int{1280, 1408, 1500, 4064, 9000, 65535}

// ---------------------------------------------------------------------------
// PEM Certificate Chain Utilities
// Source: CertPemManager.cs ParsePemChain(), ExportCertToPem(), GetCertSha256Thumbprint()
// ---------------------------------------------------------------------------

// ParsePEMChain splits a concatenated PEM string into individual PEM certificate strings.
// Normalizes CRLF → LF, strips whitespace from base64 content, and reconstructs
// each cert as a clean "-----BEGIN CERTIFICATE-----\n<base64>\n-----END CERTIFICATE-----\n".
// Source: CertPemManager.ParsePemChain()
func ParsePEMChain(pemChain string) []string {
	const beginMarker = "-----BEGIN CERTIFICATE-----"
	const endMarker = "-----END CERTIFICATE-----"

	pemChain = strings.ReplaceAll(pemChain, "\r\n", "\n")
	pemChain = strings.ReplaceAll(pemChain, "\r", "\n")

	var certs []string
	idx := 0
	for idx < len(pemChain) {
		beginIdx := strings.Index(pemChain[idx:], beginMarker)
		if beginIdx == -1 {
			break
		}
		beginIdx += idx

		endIdx := strings.Index(pemChain[beginIdx:], endMarker)
		if endIdx == -1 {
			break
		}
		endIdx += beginIdx

		// Extract base64 content between markers
		b64Content := pemChain[beginIdx+len(beginMarker) : endIdx]
		// Remove all whitespace
		var cleanB64 strings.Builder
		for _, c := range b64Content {
			if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
				cleanB64.WriteRune(c)
			}
		}

		normalized := fmt.Sprintf("%s\n%s\n%s\n", beginMarker, cleanB64.String(), endMarker)
		certs = append(certs, normalized)
		idx = endIdx + len(endMarker)
	}
	return certs
}

// ExportCertToPEM converts an x509.Certificate to PEM format (base64 DER, no line breaks
// in content, matching v2rayN's ExportCertToPem() output format).
func ExportCertToPEM(cert *x509.Certificate) string {
	b64 := base64.StdEncoding.EncodeToString(cert.Raw)
	return fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", b64)
}

// CertSHA256Thumbprint returns the uppercase hex SHA-256 thumbprint of a PEM certificate.
// Source: CertPemManager.GetCertSha256Thumbprint()
func CertSHA256Thumbprint(pemCert string) (string, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return "", fmt.Errorf("CertSHA256Thumbprint: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("CertSHA256Thumbprint: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	var sb strings.Builder
	for _, b := range sum {
		fmt.Fprintf(&sb, "%02X", b)
	}
	return sb.String(), nil
}

// ---------------------------------------------------------------------------
// Trusted CA Thumbprint Set
// Source: CertPemManager.cs TrustedCaThumbprints (186 entries)
// Used by the CA-pinning TLS validation callback.
// ---------------------------------------------------------------------------

// TrustedCAThumbprints is the set of SHA-256 root CA thumbprints trusted by
// v2rayN's CertPemManager for pinned certificate validation. Any server
// certificate whose chain roots to one of these CAs is accepted.
// Thumbprints are uppercase hex strings without colons.
var TrustedCAThumbprints = map[string]struct{}{
	"EBD41040E4BB3EC742C9E381D31EF2A41A48B6685C96E7CEF3C1DF6CD4331C99": {}, // GlobalSign Root CA
	"6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177": {}, // Entrust Premium 2048
	"73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C": {}, // Entrust Root CA
	"96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6": {}, // ISRG Root X1
	"69729B8E15A86EFC177A57AFB7171DFC64ADD28C2FCA8CF1507E34453CCB1470": {}, // ISRG Root X2
	"4348A0E9444C78CB265E058D5E8944B4D84F9662BD26DB257F8934A443C70161": {}, // DigiCert Global Root CA
	"7431E5F4C3C1CE4690774F0B61E05440883BA9A01ED00BA6ABD7806ED3B118CF": {}, // DigiCert High Assurance EV Root
	"CB3CCBB76031E5E0138F8DD39A23F9DE47FFC35E43C1144CEA27D46A5AB1CB5F": {}, // DigiCert Global Root G2
	"52F0E1C4E58EC629291B60317F074671B85D7EA80D5B07273463534B32B40234": {}, // COMODO RSA CA
	"C0A6F4DC63A24BFDCF54EF2A6A082A0A72DE35803E2FF5FF527AE5D87206DFD5": {}, // ePKI Root CA
	"CBB522D7B7F127AD6A0113865BDF1CD4102E7D0759AF635A7CF4720DC963C53B": {}, // GlobalSign Root CA-R3
	"D43AF9B35473755C9684FC06D7D8CB70EE5C28E773FB294EB41EE71722924D24": {}, // UCA Extended Validation Root
	"8ECDE6884F3D87B1125BA31AC3FCB13D7016DE7F57CC904FE1CB97C6AE98196E": {}, // Amazon Root CA 1
	"E3B6A2DB2ED7CE48842F7AC53241C7B71D54144BFB40C11F3F1D0B42F5EEA12D": {}, // Certigna
	"3E9099B5015E8F486C00BCEA9D111EE721FABA355A89BCF1DF69561E3DC6325C": {}, // DigiCert Assured ID Root CA
	"2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5": {}, // Starfield Root CA-G2
	"568D6905A2C88708A4B3025190EDCFEDB1974A606A13C6E5290FCB2AE63EDAB5": {}, // Starfield Services Root CA-G2
	"358DF39D764AF9E1B766E9C972DF352EE15CFAC227AF6AD1D70E8E4A6EDCBA02": {}, // Microsoft ECC Root CA 2017
	"C741F70F4B2A8D88BF2E71C14122EF53EF10EBA0CFA5E64CFA20F418853073E0": {}, // Microsoft RSA Root CA 2017
	"D947432ABDE7B7FA90FC2E6B59101B1280E0E1C7E4E40FA3C6887FFF57A7F4CF": {}, // GTS Root R1
	"8D25CD97229DBF70356BDA4EB3CC734031E24CF00FAFCFD32DC76EB5841C7EA8": {}, // GTS Root R2
	"34D8A73EE208D9BCDB0D956520934B4E40E69482596E8B6F73C8426B010A6F48": {}, // GTS Root R3
	"349DFA4058C5E263123B398AE795573C4E1313C83FE68F93556CD5E8031B3C7D": {}, // GTS Root R4
}

// IsTrustedCAThumbprint returns true if the given SHA-256 thumbprint (uppercase hex,
// no colons) is in the trusted CA set.
func IsTrustedCAThumbprint(thumbprint string) bool {
	_, ok := TrustedCAThumbprints[strings.ToUpper(thumbprint)]
	return ok
}

// FetchServerCertPEM connects to addr (host:port) with the given serverName
// and returns the leaf certificate PEM, validating against the trusted CA set.
// timeout controls the TLS handshake deadline.
// Source: CertPemManager.GetCertPemAsync()
func FetchServerCertPEM(addr, serverName string, timeout time.Duration) (string, error) {
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("FetchServerCertPEM: dial %s: %w", addr, err)
	}
	defer rawConn.Close()

	tlsConf := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // we do manual CA pinning below
	}
	tlsConn := tls.Client(rawConn, tlsConf)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		return "", fmt.Errorf("FetchServerCertPEM: TLS handshake: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("FetchServerCertPEM: no peer certificates")
	}

	// Validate root CA against trusted set
	if len(state.VerifiedChains) > 0 {
		rootChain := state.VerifiedChains[0]
		root := rootChain[len(rootChain)-1]
		sum := sha256.Sum256(root.Raw)
		var tp strings.Builder
		for _, b := range sum {
			fmt.Fprintf(&tp, "%02X", b)
		}
		if !IsTrustedCAThumbprint(tp.String()) {
			return "", fmt.Errorf("FetchServerCertPEM: root CA not in trusted set: %s", tp.String())
		}
	}

	leaf := state.PeerCertificates[0]
	return ExportCertToPEM(leaf), nil
}

// ---------------------------------------------------------------------------
// URL parsing utility
// Source: Utils.cs ParseUrl() + ParseAuthority()
// ---------------------------------------------------------------------------

// ParseProxyURL parses a proxy URL (including non-standard schemes) into
// (domain, scheme, port, path). Falls back gracefully if standard parsing fails.
// Source: Utils.ParseUrl()
func ParseProxyURL(rawURL string) (domain, scheme string, port int, path string) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", "", 0, ""
	}

	// Standard URI parse attempt
	// Use net/url manually to avoid import cycle — inline the logic
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd > 0 {
		scheme = rawURL[:schemeEnd]
		rest := rawURL[schemeEnd+3:]

		// Split authority from path
		pathIdx := strings.IndexAny(rest, "/?#")
		authority := rest
		if pathIdx >= 0 {
			path = rest[pathIdx:]
			authority = rest[:pathIdx]
		}

		// Strip userinfo
		if atIdx := strings.LastIndex(authority, "@"); atIdx > 0 {
			authority = authority[atIdx+1:]
		}

		domain, port = parseAuthority(authority)
		return domain, scheme, port, path
	}

	// No scheme — treat whole string as authority
	domain, port = parseAuthority(rawURL)
	return domain, "", port, ""
}

func parseAuthority(authority string) (string, int) {
	if authority == "" {
		return "", 0
	}
	// IPv6
	if strings.HasPrefix(authority, "[") && strings.Contains(authority, "]") {
		closeBracket := strings.LastIndex(authority, "]")
		if closeBracket < len(authority)-1 && authority[closeBracket+1] == ':' {
			portStr := authority[closeBracket+2:]
			var p int
			fmt.Sscan(portStr, &p)
			return authority[:closeBracket+1], p
		}
		return authority, 0
	}
	// IPv4 / hostname
	if lastColon := strings.LastIndex(authority, ":"); lastColon > 0 {
		portStr := authority[lastColon+1:]
		allDigits := true
		for _, c := range portStr {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(portStr) > 0 {
			var p int
			fmt.Sscan(portStr, &p)
			return authority[:lastColon], p
		}
	}
	return authority, 0
}
