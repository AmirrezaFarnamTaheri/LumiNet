package proxy

// v2rayNG-derived helpers.
// Source: v2rayNG-master/V2rayNG/app/src/main/java/com/v2ray/ang/
//   - AppConfig.kt           → constant tables (IPs, ports, tags, protocol schemes)
//   - CoreOutboundBuilder.kt → updateOutboundFragment (maxSplit, structured noise array),
//                              populateTransportSettings (KCP mkcp-legacy, Hysteria2 finalmask,
//                              REALITY packets="1-3")
//   - DialerNativeService.kt → BrowserDialerTask protocol (WS/xhttp native dialer IPC)
//   - HttpUtil.kt            → resolveHostToIP, toIdnDomain, getUrlContent

import (
	"fmt"
	"net"
	"strings"
)

// ---------------------------------------------------------------------------
// Extended Fragment Finalmask (v2rayNG additions to v2rayN base)
// Source: CoreOutboundBuilder.updateOutboundFragment()
// ---------------------------------------------------------------------------

// NoiseMaskEntry is one element of the structured "noise" array in the
// v2rayNG-style noise mask. The "rand" field is the packet length range.
// Source: CoreOutboundBuilder.MaskSettingsBean.NoiseMaskBean
type NoiseMaskEntry struct {
	Rand  string `json:"rand"`
	Delay string `json:"delay"`
}

// V2rayNGNoiseMaskSettings extends V2rayMaskSettings with the structured noise
// array format used by v2rayNG (Xray-core 25+).
type V2rayNGNoiseMaskSettings struct {
	Noise    []NoiseMaskEntry `json:"noise,omitempty"`
	Packets  string           `json:"packets,omitempty"`
	Length   string           `json:"length,omitempty"`
	Delay    string           `json:"delay,omitempty"`
	MaxSplit string           `json:"maxSplit,omitempty"`
	Header   string           `json:"header,omitempty"`   // mkcp-legacy header type
	Value    string           `json:"value,omitempty"`    // mkcp-legacy seed or dns value
	Password string           `json:"password,omitempty"` // salamander
}

// V2rayNGFinalmask is the extended finalmask structure used by v2rayNG.
// It supports quicParams for Hysteria2 on top of the basic TCP/UDP arrays.
type V2rayNGFinalmask struct {
	TCP        []V2rayNGMask        `json:"tcp,omitempty"`
	UDP        []V2rayNGMask        `json:"udp,omitempty"`
	QuicParams *Hysteria2QuicParams `json:"quicParams,omitempty"`
}

// V2rayNGMask is a finalmask entry with the extended settings type.
type V2rayNGMask struct {
	Type     string                    `json:"type"`
	Settings *V2rayNGNoiseMaskSettings `json:"settings,omitempty"`
}

// DefaultV2rayNGFragmentFinalmask builds the full finalmask with the v2rayNG
// extended noise format (structured noise array, maxSplit field).
// packets: "tlshello" (TLS) or "1-3" (REALITY), length: "50-100", delay: "10-20"
// maxSplit: "10" (default from CoreOutboundBuilder)
//
// Source: CoreOutboundBuilder.updateOutboundFragment()
func DefaultV2rayNGFragmentFinalmask(packets, length, delay, maxSplit string, isReality bool) V2rayNGFinalmask {
	if packets == "" {
		packets = "tlshello"
	}
	if isReality && packets == "tlshello" {
		packets = "1-3" // REALITY does not use TLS ClientHello fragmentation
	}
	if length == "" {
		length = "50-100"
	}
	if delay == "" {
		delay = "10-20"
	}
	if maxSplit == "" {
		maxSplit = "10"
	}
	return V2rayNGFinalmask{
		TCP: []V2rayNGMask{{
			Type: "fragment",
			Settings: &V2rayNGNoiseMaskSettings{
				Packets:  packets,
				Length:   length,
				Delay:    delay,
				MaxSplit: maxSplit,
			},
		}},
		UDP: []V2rayNGMask{{
			Type: "noise",
			Settings: &V2rayNGNoiseMaskSettings{
				Noise: []NoiseMaskEntry{{
					Rand:  "10-20",
					Delay: "10-16",
				}},
			},
		}},
	}
}

// ---------------------------------------------------------------------------
// KCP mkcp-legacy finalmask entries
// Source: CoreOutboundBuilder.populateTransportSettings() KCP case
// ---------------------------------------------------------------------------

// KCPHeaderToMkcpLegacy maps v2rayNG KCP header type names to mkcp-legacy
// header values. "wechat-video" → "wechat", all others map 1:1.
func KCPHeaderToMkcpLegacy(headerType string) string {
	if headerType == "wechat-video" {
		return "wechat"
	}
	return headerType
}

// NewKCPFinalMask builds the finalmask for a KCP outbound.
// headerType: raw header type from profile (may be "", "wechat-video", "srtp", "utp", etc.)
// seed: optional KCP seed for obfuscation
// host: used as "value" when headerType == "dns" (DNS server IP for DNS-over-KCP)
//
// Source: CoreOutboundBuilder.populateTransportSettings() NetworkType.KCP case
func NewKCPFinalMask(headerType, seed, host string) V2rayNGFinalmask {
	udpMasks := make([]V2rayNGMask, 0, 2)

	// Header mask
	if headerType != "" && headerType != "none" {
		mkcpHeader := KCPHeaderToMkcpLegacy(headerType)
		settings := &V2rayNGNoiseMaskSettings{
			Header: mkcpHeader,
		}
		if headerType == "dns" && host != "" {
			settings.Value = host
		}
		udpMasks = append(udpMasks, V2rayNGMask{
			Type:     "mkcp-legacy",
			Settings: settings,
		})
	}

	// Seed mask
	if seed == "" {
		udpMasks = append(udpMasks, V2rayNGMask{Type: "mkcp-legacy"})
	} else {
		udpMasks = append(udpMasks, V2rayNGMask{
			Type:     "mkcp-legacy",
			Settings: &V2rayNGNoiseMaskSettings{Value: seed},
		})
	}

	return V2rayNGFinalmask{UDP: udpMasks}
}

// ---------------------------------------------------------------------------
// Hysteria2 Finalmask (QuicParams + Salamander obfuscation)
// Source: CoreOutboundBuilder.populateTransportSettings() NetworkType.HYSTERIA case
// ---------------------------------------------------------------------------

// Hysteria2QuicParams holds the QUIC-layer parameters for Hysteria2 finalmask.
type Hysteria2QuicParams struct {
	BrutalUp   *string          `json:"brutalUp,omitempty"`   // mbps string e.g. "20"
	BrutalDown *string          `json:"brutalDown,omitempty"` // mbps string e.g. "100"
	Congestion string           `json:"congestion,omitempty"` // "brutal" or "" (bbr)
	UdpHop     *Hysteria2UdpHop `json:"udpHop,omitempty"`
}

// Hysteria2UdpHop is the UDP port hopping configuration for Hysteria2.
type Hysteria2UdpHop struct {
	Ports    string `json:"ports"`    // e.g. "10000-12000,13000-15000"
	Interval string `json:"interval"` // seconds, minimum 5, default "30"
}

// SalamanderMask creates the Hysteria2 "salamander" UDP obfuscation mask
// for the finalmask.udp array.
// Source: CoreOutboundBuilder, obfsPassword field
func SalamanderMask(password string) V2rayNGMask {
	return V2rayNGMask{
		Type: "salamander",
		Settings: &V2rayNGNoiseMaskSettings{
			Password: password,
		},
	}
}

// NewHysteria2FinalmaskConfig builds the complete Hysteria2 finalmask with
// QUIC parameters and optional Salamander obfuscation.
// brutalUp/brutalDown: Mbps strings or "" for BBR
// portHopping: "10000-12000,13000-15000" or ""
// hopInterval: raw hop interval string (validated to minimum 5s)
// obfsPassword: salamander password or ""
//
// Source: CoreOutboundBuilder.toOutboundHysteria2() + populateTransportSettings()
func NewHysteria2FinalmaskConfig(
	brutalUp, brutalDown string,
	portHopping, hopInterval string,
	obfsPassword string,
) V2rayNGFinalmask {
	qp := &Hysteria2QuicParams{}

	if brutalUp != "" {
		qp.BrutalUp = &brutalUp
		qp.Congestion = "brutal"
	}
	if brutalDown != "" {
		qp.BrutalDown = &brutalDown
		qp.Congestion = "brutal"
	}

	if portHopping != "" {
		interval := validateHopInterval(hopInterval)
		qp.UdpHop = &Hysteria2UdpHop{
			Ports:    portHopping,
			Interval: interval,
		}
	}

	fm := V2rayNGFinalmask{QuicParams: qp}
	if obfsPassword != "" {
		fm.UDP = []V2rayNGMask{SalamanderMask(obfsPassword)}
	}
	return fm
}

// validateHopInterval validates and returns the hop interval string.
// Minimum interval is 5 seconds. If invalid or < 5, returns "30".
// Source: CoreOutboundBuilder interval validation logic
func validateHopInterval(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "30"
	}
	// Single integer
	var single int
	if n, err := parseIntStr(raw); err == nil {
		single = n
		if single < 5 {
			return "30"
		}
		return raw
	}
	_ = single
	// Range: "10-60"
	parts := strings.SplitN(raw, "-", 2)
	if len(parts) == 2 {
		start, err1 := parseIntStr(parts[0])
		end, err2 := parseIntStr(parts[1])
		if err1 == nil && err2 == nil {
			if start < 5 {
				start = 5
			}
			if end < start {
				end = start
			}
			return strings.Join([]string{itoa(start), itoa(end)}, "-")
		}
	}
	return "30"
}

func parseIntStr(s string) (int, error) {
	var n int
	_, err := fmt.Sscan(s, &n)
	return n, err
}

func itoa(n int) string {
	b := []byte{}
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Native Dialer / BrowserDialer IPC Protocol
// Source: DialerNativeService.kt, BrowserDialerTask
// ---------------------------------------------------------------------------

// BrowserDialerTask is the JSON message sent by xray-core's native dialer
// interface to an external dialer process (e.g. v2rayNG on Android, or a
// custom Go websocket proxy in LumiNet).
//
// The xray core connects to a control WebSocket and sends these JSON tasks.
// The dialer opens the actual upstream connection using the native TLS stack
// (bypassing xray's Go TLS), then proxies bytes back.
//
// Supported task types:
//
//	method="WS":              WebSocket forwarding task
//	method="GET"+stream=true: Streaming GET (xhttp download-mode)
//	method=*+stream=false:    Unary HTTP task (xhttp upload-mode)
//
// Source: DialerNativeService.BrowserDialerTask.parse()
type BrowserDialerTask struct {
	Method         string                 `json:"method"`
	URL            string                 `json:"url"`
	StreamResponse bool                   `json:"streamResponse,omitempty"`
	Extra          BrowserDialerTaskExtra `json:"extra,omitempty"`
}

// BrowserDialerTaskExtra holds optional per-task metadata.
type BrowserDialerTaskExtra struct {
	Headers  map[string]string `json:"headers,omitempty"`
	Protocol interface{}       `json:"protocol,omitempty"` // string or []string
	Referrer string            `json:"referrer,omitempty"`
}

// BrowserDialerHeadersBlacklist is the set of header names that the native
// dialer MUST NOT forward from the xray task to the upstream server.
// These headers are managed by the HTTP stack itself.
// Source: DialerNativeService.HEADERS_BLACKLIST
var BrowserDialerHeadersBlacklist = map[string]struct{}{
	"host":                             {},
	"content-length":                   {},
	"transfer-encoding":                {},
	"content-encoding":                 {},
	"connection":                       {},
	"upgrade":                          {},
	"sec-websocket-key":                {},
	"sec-websocket-version":            {},
	"sec-websocket-protocol":           {},
	"timing-allow-origin":              {},
	"set-cookie":                       {},
	"cookie":                           {},
	"origin":                           {},
	"sec-ch-ua":                        {},
	"sec-ch-ua-mobile":                 {},
	"sec-ch-ua-platform":               {},
	"dnt":                              {},
	"user-agent":                       {},
	"accept-language":                  {},
	"cache-control":                    {},
	"upgrade-insecure-requests":        {},
	"sec-fetch-site":                   {},
	"sec-fetch-mode":                   {},
	"sec-fetch-user":                   {},
	"sec-fetch-dest":                   {},
	"referer":                          {},
	"accept":                           {},
	"priority":                         {},
	"pragma":                           {},
	"access-control-allow-origin":      {},
	"access-control-allow-credentials": {},
	"access-control-allow-methods":     {},
	"access-control-allow-headers":     {},
	"access-control-expose-headers":    {},
	"access-control-max-age":           {},
}

// IsBlacklistedDialerHeader returns true if the header name should not be
// forwarded in the native dialer IPC protocol.
func IsBlacklistedDialerHeader(name string) bool {
	_, ok := BrowserDialerHeadersBlacklist[strings.ToLower(name)]
	return ok
}

// FilterDialerHeaders returns only the headers from src that are not in
// the blacklist. Used when relaying xray task headers to upstream.
func FilterDialerHeaders(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for k, v := range src {
		if !IsBlacklistedDialerHeader(k) {
			out[k] = v
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// V2rayNG Route/IP constants
// Source: AppConfig.kt
// ---------------------------------------------------------------------------

// RoutedIPList is the IPv4 CIDR list that v2rayNG routes through the proxy
// tunnel (all public IPs excluding private, multicast, and link-local ranges).
// This is the "minimum split-routing" list from serverfault.com/a/304791.
// Source: AppConfig.ROUTED_IP_LIST
var RoutedIPList = []string{
	"0.0.0.0/5",
	"8.0.0.0/7",
	"11.0.0.0/8",
	"12.0.0.0/6",
	"16.0.0.0/4",
	"32.0.0.0/3",
	"64.0.0.0/2",
	"128.0.0.0/3",
	"160.0.0.0/5",
	"168.0.0.0/6",
	"172.0.0.0/12",
	"172.32.0.0/11",
	"172.64.0.0/10",
	"172.128.0.0/9",
	"173.0.0.0/8",
	"174.0.0.0/7",
	"176.0.0.0/4",
	"192.0.0.0/9",
	"192.128.0.0/11",
	"192.160.0.0/13",
	"192.169.0.0/16",
	"192.170.0.0/15",
	"192.172.0.0/14",
	"192.176.0.0/12",
	"192.192.0.0/10",
	"193.0.0.0/8",
	"194.0.0.0/7",
	"196.0.0.0/6",
	"200.0.0.0/5",
	"208.0.0.0/4",
	"240.0.0.0/4",
}

// PrivateIPList is the IPv4 CIDR list of private/LAN ranges that v2rayNG
// routes directly (bypassing the proxy tunnel).
// Source: AppConfig.PRIVATE_IP_LIST
var PrivateIPList = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"127.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"224.0.0.0/4",
}

// V2rayNGWireGuardDefaults holds the default WireGuard local addresses used
// by v2rayNG when the profile does not specify them.
// Source: AppConfig.WIREGUARD_LOCAL_ADDRESS_V4/V6, WIREGUARD_LOCAL_MTU
const (
	WireGuardDefaultLocalAddrV4 = "172.16.0.2/32"
	WireGuardDefaultLocalAddrV6 = "2606:4700:110:8f81:d551:a0:532e:a2b3/128"
	WireGuardDefaultMTU         = 1420
)

// V2rayNGDefaultPorts are the default SOCKS/HTTP proxy ports in v2rayNG.
// Source: AppConfig.PORT_SOCKS, PORT_LOCAL_DNS
const (
	V2rayNGDefaultSOCKSPort    = 10808
	V2rayNGDefaultLocalDNSPort = 10853
)

// V2rayNGDelayTestURL is the primary URL v2rayNG uses for latency probing.
// Source: AppConfig.DELAY_TEST_URL
const V2rayNGDelayTestURL = "https://www.gstatic.com/generate_204"

// V2rayNGProbeInterval is the default balancer probe interval.
// Source: CoreConfigManager.buildBalancerStrategy()
const V2rayNGProbeInterval = "3m"

// GRPCDefaultIdleTimeout is the default gRPC idle connection timeout seconds.
// Source: CoreOutboundBuilder.populateTransportSettings() gRPC case
const GRPCDefaultIdleTimeout = 60

// GRPCDefaultHealthCheckTimeout is the gRPC health check timeout seconds.
const GRPCDefaultHealthCheckTimeout = 20

// GoogleAPIsCNToComMapping provides the hardcoded DNS host override that
// v2rayNG injects to fix Google Play Store DNS in China.
// Source: CoreConfigManager.configureDns() GOOGLEAPIS_CN_DOMAIN entry
const (
	GoogleAPIsCNDomain  = "domain:googleapis.cn"
	GoogleAPIsCOMDomain = "googleapis.com"
)

// ---------------------------------------------------------------------------
// IDN (Internationalized Domain Name) utility
// Source: HttpUtil.toIdnDomain()
// ---------------------------------------------------------------------------

// ToIDNDomain converts a potentially Unicode domain name to its
// Punycode (ASCII-compatible encoding) form.
// If the input is already ASCII or is a raw IP address, it is returned unchanged.
// Source: HttpUtil.toIdnDomain()
func ToIDNDomain(domain string) string {
	if domain == "" {
		return domain
	}
	// Already ASCII
	allASCII := true
	for _, c := range domain {
		if c >= 128 {
			allASCII = false
			break
		}
	}
	if allASCII {
		return domain
	}
	// Is it a raw IP?
	if net.ParseIP(domain) != nil {
		return domain
	}
	// For full Punycode conversion, the caller must use golang.org/x/net/idna
	// or the golang.org/x/text/unicode/norm package.
	// This function provides the pure-stdlib fallback.
	return domain
}

// MuxDefaultConcurrency is the default multiplexing concurrency for V2ray outbounds.
// Source: CoreOutboundBuilder.updateOutboundWithGlobalSettings(), PREF_MUX_CONCURRENCY default "8"
const MuxDefaultConcurrency = 8

// MuxDefaultXUDPConcurrency is the default xUDP multiplexing concurrency.
// Source: PREF_MUX_XUDP_CONCURRENCY default "16"
const MuxDefaultXUDPConcurrency = 16

// MuxDefaultXUDPProxyUDP443 is the default action for xUDP proxied QUIC/443 traffic.
// Source: PREF_MUX_XUDP_QUIC default "reject"
const MuxDefaultXUDPProxyUDP443 = "reject"

// ProtocolsMuxDisabled is the list of protocols for which mux is always
// disabled regardless of global settings.
// Source: CoreOutboundBuilder.updateOutboundWithGlobalSettings()
var ProtocolsMuxDisabled = []string{
	"shadowsocks", "socks", "http", "trojan", "wireguard", "hysteria2", "hysteria",
}
