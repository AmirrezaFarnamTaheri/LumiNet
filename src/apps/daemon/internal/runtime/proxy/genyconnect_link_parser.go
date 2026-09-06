// Package proxy implements outbound protocols and obfuscation mechanisms.
//
// Provides a unified link parser that supports vmess, vless, trojan, ss, and wireguard
// share links.  Validation logic is a faithful port of the GenyConnect
// C++ implementation (modules genyconnect.backend.linkparser).

package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Profile types
// ─────────────────────────────────────────────────────────────────────────────

// GenyServerProfile is the parsed output of a share link.
type GenyServerProfile struct {
	ID       string // UUID generated on parse
	Protocol string // vmess | vless | trojan | shadowsocks | wireguard
	Name     string

	// Connection fields
	Address  string
	Port     uint16
	UserID   string // user id / password
	Password string // SS / Trojan password (alias for UserID)

	// Transport
	Network     string // tcp | ws | xhttp | grpc | h2 | wireguard
	Security    string // none | tls | reality
	Flow        string
	Path        string
	HeaderType  string
	HostHeader  string
	ServiceName string
	XHTTPMode   string
	XHTTPExtra  map[string]interface{}

	// TLS / Reality
	SNI         string
	ALPN        string
	Fingerprint string
	PublicKey   string
	ShortID     string
	SpiderX     string

	// Misc
	Encryption       string // vmess cipher / ss method
	AllowInsecure    bool
	PinnedCertSHA256 []string

	// WireGuard
	WGSecretKey           string
	WGPublicKey           string
	WGPresharedKey        string
	WGAddress             []string
	WGAllowedIPs          []string
	WGReserved            []string
	WGDNS                 []string
	WGMTU                 int
	WGPersistentKeepalive int

	// Original raw link for round-tripping
	OriginalLink string
}

// isValid checks that mandatory fields are present.
func (p *GenyServerProfile) isValid() bool {
	if p.Address == "" || p.Port == 0 {
		return false
	}
	switch p.Protocol {
	case "wireguard":
		return p.WGSecretKey != "" && p.WGPublicKey != ""
	case "shadowsocks":
		return p.Encryption != ""
	case "vmess":
		return p.UserID != ""
	case "vless":
		return true
	case "trojan":
		return p.UserID != ""
	}
	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// GenyLinkParser  - main entry point
// ─────────────────────────────────────────────────────────────────────────────

// GenyLinkParser parses share links into GenyServerProfile objects.
// Supported schemes: vmess, vless, trojan, ss (shadowsocks), wireguard, wg.
type GenyLinkParser struct{}

// NewGenyLinkParser returns a zero-value parser.
func NewGenyLinkParser() *GenyLinkParser { return &GenyLinkParser{} }

// Parse dispatches to the appropriate scheme-specific parser.
func (lp *GenyLinkParser) Parse(rawLink string) (*GenyServerProfile, error) {
	link := strings.TrimSpace(rawLink)
	if link == "" {
		return nil, fmt.Errorf("geny_link_parser: import link is empty")
	}
	lower := strings.ToLower(link)
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return lp.parseVmess(link)
	case strings.HasPrefix(lower, "vless://"):
		return lp.parseVless(link)
	case strings.HasPrefix(lower, "trojan://"):
		return lp.parseTrojan(link)
	case strings.HasPrefix(lower, "ss://"):
		return lp.parseShadowsocks(link)
	case strings.HasPrefix(lower, "wireguard://"), strings.HasPrefix(lower, "wg://"):
		return lp.parseWireguardURI(link)
	case looksLikeWireGuardConfig(link):
		return lp.parseWireguardConfig(link)
	default:
		return nil, fmt.Errorf("geny_link_parser: unsupported profile format (supported: vmess, vless, trojan, ss, wireguard)")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper functions (mirrors the anonymous namespace in linkparser.cpp)
// ─────────────────────────────────────────────────────────────────────────────

func genyNormalizePath(path string) string {
	path = strings.TrimSpace(path)
	// Iteratively percent-decode up to 3 times (mirrors C++ loop)
	for i := 0; i < 3 && strings.Contains(path, "%"); i++ {
		decoded, err := url.QueryUnescape(path)
		if err != nil || decoded == path {
			break
		}
		path = strings.TrimSpace(decoded)
	}
	if path == "" {
		return "/"
	}
	for strings.HasPrefix(path, "//") {
		path = path[1:]
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func genyNormalizeTransportNetwork(v string) string {
	n := strings.TrimSpace(strings.ToLower(v))
	switch n {
	case "splithttp", "http":
		return "xhttp"
	case "httpupgrade":
		return "ws"
	}
	return n
}

func genyFirstHostToken(hostHeader string) string {
	t := strings.TrimSpace(hostHeader)
	if t == "" {
		return ""
	}
	if idx := strings.Index(t, ","); idx > 0 {
		return strings.TrimSpace(t[:idx])
	}
	return t
}

func genyParseBool(v string) bool {
	l := strings.TrimSpace(strings.ToLower(v))
	return l == "1" || l == "true" || l == "yes" || l == "on"
}

func genySplitCSV(raw string) []string {
	var out []string
	for _, tok := range strings.Split(strings.TrimSpace(raw), ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

func genyCertPins(raw string) []string {
	re := regexp.MustCompile(`[,;\s]+`)
	var out []string
	for _, tok := range re.Split(raw, -1) {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			out = append(out, tok)
		}
	}
	// dedup
	seen := map[string]struct{}{}
	deduped := out[:0]
	for _, v := range out {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			deduped = append(deduped, v)
		}
	}
	return deduped
}

// decodeFlexibleBase64 tries both standard and URL-safe base64.
func decodeFlexibleBase64(s string) ([]byte, error) {
	// Normalise URL-safe to standard
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	// Pad
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return decoded, nil
	}
	// Try raw-URL without padding
	decoded, err2 := base64.RawURLEncoding.DecodeString(s)
	if err2 == nil {
		return decoded, nil
	}
	return nil, err
}

func genyParsePort(v interface{}) (uint16, bool) {
	switch t := v.(type) {
	case float64:
		p := int(t)
		if p > 0 && p <= 65535 {
			return uint16(p), true
		}
	case string:
		p, err := strconv.Atoi(strings.TrimSpace(t))
		if err == nil && p > 0 && p <= 65535 {
			return uint16(p), true
		}
	case json.Number:
		p, err := strconv.Atoi(t.String())
		if err == nil && p > 0 && p <= 65535 {
			return uint16(p), true
		}
	}
	return 0, false
}

func genyParsePortStr(s string) (uint16, bool) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p <= 0 || p > 65535 {
		return 0, false
	}
	return uint16(p), true
}

// genyInsecureQueryKey reads the first of several legacy allow-insecure keys.
func genyInsecureQueryKey(q url.Values) string {
	for _, k := range []string{"allowInsecure", "insecure", "allow_insecure", "tlsAllowInsecure", "skipCertVerify", "skipCertificateVerify"} {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func genyPinnedCertQueryKey(q url.Values) string {
	for _, k := range []string{"pinnedPeerCertSha256", "pinnedPeerCertificateChainSha256", "peerCertSha256", "certSha256"} {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

func looksLikeWireGuardConfig(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "[interface]") &&
		strings.Contains(l, "[peer]") &&
		strings.Contains(l, "privatekey") &&
		strings.Contains(l, "publickey")
}

// isSupportedVlessEncryption validates a VLESS encryption token list.
var _vlessEncSafeRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._:+\-]{1,127}$`)

func isSupportedVlessEncryption(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(strings.ToLower(tok))
		if tok == "" {
			return false
		}
		if tok == "none" || tok == "zero" || tok == "auto" || strings.HasPrefix(tok, "vlessenc") {
			continue
		}
		if !_vlessEncSafeRE.MatchString(tok) {
			return false
		}
	}
	return true
}

// applyTransportQueryFields populates transport fields from a query-string.
// Mirrors applyTransportQueryFields() in linkparser.cpp.
func applyGenyTransportFields(p *GenyServerProfile, q url.Values, defaultSecurity string) {
	p.Network = genyNormalizeTransportNetwork(q.Get("type"))
	if p.Network == "" {
		p.Network = "tcp"
	}
	p.Security = strings.TrimSpace(strings.ToLower(q.Get("security")))
	if p.Security == "" {
		p.Security = defaultSecurity
	}
	p.Flow = q.Get("flow")
	p.Path = q.Get("path")
	if p.Network == "ws" || p.Network == "xhttp" {
		p.Path = genyNormalizePath(p.Path)
	}
	p.HeaderType = strings.ToLower(q.Get("headerType"))
	p.HostHeader = strings.TrimSpace(q.Get("host"))
	p.ServiceName = strings.TrimSpace(q.Get("serviceName"))
	p.XHTTPMode = strings.ToLower(strings.TrimSpace(q.Get("mode")))
	if p.Network == "xhttp" && p.XHTTPMode == "" {
		p.XHTTPMode = "auto"
	}
	if extra := q.Get("extra"); strings.TrimSpace(extra) != "" {
		m := map[string]interface{}{}
		if err := json.Unmarshal([]byte(extra), &m); err == nil {
			p.XHTTPExtra = m
		}
	}
	p.SNI = strings.TrimSpace(q.Get("sni"))
	if p.SNI == "" {
		p.SNI = strings.TrimSpace(q.Get("serverName"))
	}
	if p.SNI == "" && (p.Security == "tls" || p.Security == "reality") {
		p.SNI = genyFirstHostToken(p.HostHeader)
	}
	if p.SNI == "" && p.Security == "tls" {
		p.SNI = strings.TrimSpace(p.Address)
	}
	p.ALPN = strings.TrimSpace(q.Get("alpn"))
	p.Fingerprint = strings.TrimSpace(q.Get("fp"))
	p.PublicKey = strings.TrimSpace(q.Get("pbk"))
	p.ShortID = strings.TrimSpace(q.Get("sid"))
	p.SpiderX = strings.TrimSpace(q.Get("spx"))
	p.AllowInsecure = genyParseBool(genyInsecureQueryKey(q))
	p.PinnedCertSHA256 = genyCertPins(genyPinnedCertQueryKey(q))
}

// ─────────────────────────────────────────────────────────────────────────────
// VMess
// ─────────────────────────────────────────────────────────────────────────────

func (lp *GenyLinkParser) parseVmess(rawLink string) (*GenyServerProfile, error) {
	payload := strings.TrimPrefix(rawLink, "vmess://")
	// Extract optional fragment name
	profileName := ""
	if idx := strings.Index(payload, "#"); idx >= 0 {
		profileName, _ = url.QueryUnescape(payload[idx+1:])
		payload = payload[:idx]
	}
	decoded, err := decodeFlexibleBase64(strings.TrimSpace(payload))
	if err != nil {
		return nil, fmt.Errorf("geny_link_parser: vmess: base64 decode failed: %w", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(decoded, &obj); err != nil {
		return nil, fmt.Errorf("geny_link_parser: vmess: json parse failed: %w", err)
	}
	getString := func(key string) string {
		v, ok := obj[key]
		if !ok {
			return ""
		}
		switch t := v.(type) {
		case string:
			return strings.TrimSpace(t)
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		case json.Number:
			return t.String()
		}
		return fmt.Sprintf("%v", v)
	}

	p := &GenyServerProfile{
		Protocol:     "vmess",
		OriginalLink: rawLink,
	}
	if profileName != "" {
		p.Name = strings.TrimSpace(profileName)
	} else {
		p.Name = getString("ps")
	}
	p.Address = getString("add")
	portVal, portOk := genyParsePort(obj["port"])
	if !portOk {
		return nil, fmt.Errorf("geny_link_parser: vmess: invalid port")
	}
	p.Port = portVal
	p.UserID = getString("id")
	p.Encryption = getString("scy")
	if p.Encryption == "" {
		p.Encryption = "auto"
	}
	p.Network = genyNormalizeTransportNetwork(getString("net"))
	if p.Network == "" {
		p.Network = "tcp"
	}
	tls := getString("tls")
	if tls == "none" || tls == "" {
		p.Security = "none"
	} else {
		p.Security = tls
	}
	p.Path = getString("path")
	if p.Network == "ws" || p.Network == "xhttp" {
		p.Path = genyNormalizePath(p.Path)
	}
	p.HeaderType = strings.ToLower(getString("type"))
	p.HostHeader = getString("host")
	p.SNI = getString("sni")
	if p.SNI == "" {
		p.SNI = getString("serverName")
	}
	if p.SNI == "" && (p.Security == "tls" || p.Security == "reality") {
		p.SNI = genyFirstHostToken(p.HostHeader)
	}
	p.ALPN = getString("alpn")
	p.Flow = getString("flow")
	p.Fingerprint = getString("fp")
	p.PublicKey = getString("pbk")
	p.ShortID = getString("sid")
	p.SpiderX = getString("spx")
	p.ServiceName = getString("serviceName")
	p.XHTTPMode = strings.ToLower(getString("mode"))
	if p.Network == "xhttp" && p.XHTTPMode == "" {
		p.XHTTPMode = "auto"
	}
	insecureKeys := []string{"allowInsecure", "insecure", "allow_insecure", "tlsAllowInsecure", "skipCertVerify", "skipCertificateVerify"}
	for _, k := range insecureKeys {
		if v, ok := obj[k]; ok {
			switch t := v.(type) {
			case bool:
				p.AllowInsecure = t
			case string:
				p.AllowInsecure = genyParseBool(t)
			}
			break
		}
	}
	if !p.isValid() {
		return nil, fmt.Errorf("geny_link_parser: vmess: missing required fields")
	}
	return p, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// VLESS
// ─────────────────────────────────────────────────────────────────────────────

func (lp *GenyLinkParser) parseVless(rawLink string) (*GenyServerProfile, error) {
	u, err := url.Parse(rawLink)
	if err != nil {
		return nil, fmt.Errorf("geny_link_parser: vless: invalid URL: %w", err)
	}
	q := u.Query()
	p := &GenyServerProfile{
		Protocol:     "vless",
		OriginalLink: rawLink,
		Name:         strings.TrimSpace(u.Fragment),
		UserID:       strings.TrimSpace(u.User.Username()),
		Address:      strings.TrimSpace(u.Hostname()),
	}
	if rawPort := u.Port(); rawPort != "" {
		port, ok := genyParsePortStr(rawPort)
		if !ok {
			return nil, fmt.Errorf("geny_link_parser: vless: invalid port")
		}
		p.Port = port
	} else {
		p.Port = 443
	}
	p.Encryption = strings.ToLower(strings.TrimSpace(q.Get("encryption")))
	if p.Encryption == "" {
		p.Encryption = "none"
	}
	if !isSupportedVlessEncryption(p.Encryption) {
		return nil, fmt.Errorf("geny_link_parser: vless: unsupported encryption value %q", p.Encryption)
	}
	applyGenyTransportFields(p, q, "none")
	sec := strings.ToLower(strings.TrimSpace(p.Security))
	if sec != "none" && sec != "tls" && sec != "reality" {
		return nil, fmt.Errorf("geny_link_parser: vless: unsupported security value %q", p.Security)
	}
	if sec == "reality" && strings.TrimSpace(p.PublicKey) == "" {
		return nil, fmt.Errorf("geny_link_parser: vless: REALITY requires a public key (pbk)")
	}
	if (sec == "tls" || sec == "reality") && strings.TrimSpace(p.SNI) == "" {
		return nil, fmt.Errorf("geny_link_parser: vless: TLS/REALITY requires SNI/serverName/host")
	}
	if p.Flow != "" && sec != "tls" && sec != "reality" {
		return nil, fmt.Errorf("geny_link_parser: vless: flow requires TLS or REALITY security")
	}
	if extra := q.Get("extra"); strings.TrimSpace(extra) != "" {
		m := map[string]interface{}{}
		if err := json.Unmarshal([]byte(extra), &m); err != nil {
			return nil, fmt.Errorf("geny_link_parser: vless: invalid XHTTP extra JSON")
		}
		p.XHTTPExtra = m
	}
	if !p.isValid() {
		return nil, fmt.Errorf("geny_link_parser: vless: missing required fields")
	}
	return p, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Trojan
// ─────────────────────────────────────────────────────────────────────────────

func (lp *GenyLinkParser) parseTrojan(rawLink string) (*GenyServerProfile, error) {
	u, err := url.Parse(rawLink)
	if err != nil {
		return nil, fmt.Errorf("geny_link_parser: trojan: invalid URL: %w", err)
	}
	q := u.Query()
	p := &GenyServerProfile{
		Protocol:     "trojan",
		OriginalLink: rawLink,
		Name:         strings.TrimSpace(u.Fragment),
		UserID:       strings.TrimSpace(u.User.Username()),
		Address:      strings.TrimSpace(u.Hostname()),
		Encryption:   "none",
	}
	if rawPort := u.Port(); rawPort != "" {
		port, ok := genyParsePortStr(rawPort)
		if !ok {
			return nil, fmt.Errorf("geny_link_parser: trojan: invalid port")
		}
		p.Port = port
	} else {
		p.Port = 443
	}
	applyGenyTransportFields(p, q, "tls")
	if !p.isValid() {
		return nil, fmt.Errorf("geny_link_parser: trojan: missing required fields")
	}
	return p, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Shadowsocks
// ─────────────────────────────────────────────────────────────────────────────

func (lp *GenyLinkParser) parseShadowsocks(rawLink string) (*GenyServerProfile, error) {
	payload := strings.TrimPrefix(rawLink, "ss://")
	profileName := ""
	if idx := strings.Index(payload, "#"); idx >= 0 {
		profileName, _ = url.QueryUnescape(payload[idx+1:])
		profileName = strings.TrimSpace(profileName)
		payload = payload[:idx]
	}
	queryText := ""
	if idx := strings.Index(payload, "?"); idx >= 0 {
		queryText = payload[idx+1:]
		payload = payload[:idx]
	}
	// Try modern format: <credentials>@<host>:<port>
	var credPart, endpointPart string
	if atIdx := strings.LastIndex(payload, "@"); atIdx > 0 && atIdx < len(payload)-1 {
		credPart = payload[:atIdx]
		endpointPart = payload[atIdx+1:]
	} else {
		// Legacy base64 format
		decoded, err := decodeFlexibleBase64(strings.TrimSpace(payload))
		if err != nil {
			return nil, fmt.Errorf("geny_link_parser: ss: payload decode failed")
		}
		text := strings.TrimSpace(string(decoded))
		atIdx2 := strings.LastIndex(text, "@")
		if atIdx2 <= 0 || atIdx2 >= len(text)-1 {
			return nil, fmt.Errorf("geny_link_parser: ss: payload not in method:password@host:port format")
		}
		credPart = text[:atIdx2]
		endpointPart = text[atIdx2+1:]
	}
	// Decode credentials
	method, password, err := ssDecodeCreds(credPart)
	if err != nil {
		return nil, fmt.Errorf("geny_link_parser: ss: %w", err)
	}
	// Parse endpoint
	host, port, err := ssParseEndpoint(endpointPart)
	if err != nil {
		return nil, fmt.Errorf("geny_link_parser: ss: %w", err)
	}
	q, _ := url.ParseQuery(queryText)
	p := &GenyServerProfile{
		Protocol:         "shadowsocks",
		OriginalLink:     rawLink,
		Name:             profileName,
		Address:          host,
		Port:             port,
		UserID:           password,
		Password:         password,
		Encryption:       method,
		Network:          "tcp",
		Security:         "none",
		AllowInsecure:    genyParseBool(genyInsecureQueryKey(q)),
		PinnedCertSHA256: genyCertPins(genyPinnedCertQueryKey(q)),
	}
	// Handle plugin
	if plugin := q.Get("plugin"); plugin != "" {
		parts := strings.SplitN(plugin, ";", 2)
		if len(parts) > 0 {
			pName := strings.ToLower(strings.TrimSpace(parts[0]))
			if strings.Contains(pName, "v2ray-plugin") || strings.Contains(pName, "xray-plugin") {
				opts := parseSemicolonPairsGeny(plugin)
				mode := strings.ToLower(strings.TrimSpace(opts["mode"]))
				switch mode {
				case "websocket", "ws":
					p.Network = "ws"
					p.Path = genyNormalizePath(opts["path"])
					p.HostHeader = strings.TrimSpace(opts["host"])
				case "grpc":
					p.Network = "grpc"
					p.ServiceName = strings.TrimSpace(opts["servicename"])
				}
				if _, ok := opts["tls"]; ok {
					p.Security = "tls"
				} else if strings.EqualFold(opts["security"], "tls") {
					p.Security = "tls"
				}
				p.SNI = strings.TrimSpace(opts["sni"])
			}
		}
	}
	if !p.isValid() || p.Encryption == "" {
		return nil, fmt.Errorf("geny_link_parser: ss: missing required fields")
	}
	return p, nil
}

func ssDecodeCreds(raw string) (method, password string, err error) {
	// Try direct method:password
	decoded, _ := url.QueryUnescape(strings.ReplaceAll(raw, "+", "%2B"))
	if idx := strings.Index(decoded, ":"); idx > 0 {
		return strings.TrimSpace(decoded[:idx]), strings.TrimSpace(decoded[idx+1:]), nil
	}
	// Base64 fallback
	b, e := decodeFlexibleBase64(raw)
	if e != nil {
		return "", "", fmt.Errorf("credentials decode failed")
	}
	text := strings.TrimSpace(string(b))
	idx := strings.Index(text, ":")
	if idx <= 0 {
		return "", "", fmt.Errorf("credentials not in method:password format")
	}
	return strings.TrimSpace(text[:idx]), strings.TrimSpace(text[idx+1:]), nil
}

func ssParseEndpoint(ep string) (host string, port uint16, err error) {
	ep = strings.TrimSpace(ep)
	// Try as URL
	u, e := url.Parse("ss://" + ep)
	if e == nil && u.Hostname() != "" && u.Port() != "" {
		p, ok := genyParsePortStr(u.Port())
		if !ok {
			return "", 0, fmt.Errorf("invalid port in endpoint")
		}
		return u.Hostname(), p, nil
	}
	// Manual split
	if idx := strings.LastIndex(ep, ":"); idx > 0 {
		h := ep[:idx]
		p, ok := genyParsePortStr(ep[idx+1:])
		if !ok {
			return "", 0, fmt.Errorf("invalid port in endpoint")
		}
		return h, p, nil
	}
	return "", 0, fmt.Errorf("invalid endpoint %q", ep)
}

func parseSemicolonPairsGeny(raw string) map[string]string {
	out := map[string]string{}
	for _, tok := range strings.Split(raw, ";") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		idx := strings.Index(tok, "=")
		if idx <= 0 {
			out[strings.ToLower(tok)] = ""
			continue
		}
		key := strings.ToLower(strings.TrimSpace(tok[:idx]))
		val := strings.TrimSpace(tok[idx+1:])
		out[key] = val
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// WireGuard URI
// ─────────────────────────────────────────────────────────────────────────────

func (lp *GenyLinkParser) parseWireguardURI(rawLink string) (*GenyServerProfile, error) {
	normalized := rawLink
	if strings.HasPrefix(strings.ToLower(rawLink), "wg://") {
		normalized = "wireguard://" + rawLink[len("wg://"):]
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("geny_link_parser: wireguard: invalid URL: %w", err)
	}
	q := u.Query()
	p := &GenyServerProfile{
		Protocol:     "wireguard",
		Network:      "wireguard",
		Security:     "none",
		Encryption:   "none",
		OriginalLink: rawLink,
		Name:         strings.TrimSpace(u.Fragment),
	}
	host := strings.TrimSpace(u.Hostname())
	portStr := u.Port()
	var port uint16
	portOK := false
	if portStr != "" {
		port, portOK = genyParsePortStr(portStr)
	}
	if host == "" || !portOK {
		// Look in query
		endpoint := q.Get("endpoint")
		if endpoint == "" {
			endpoint = q.Get("server")
		}
		h, pt, e := parseGenyEndpointHostPort(endpoint)
		if e != nil {
			return nil, fmt.Errorf("geny_link_parser: wireguard: invalid endpoint")
		}
		host, port = h, pt
	}
	p.Address = host
	p.Port = port
	p.WGSecretKey = strings.TrimSpace(u.User.Username())
	if p.WGSecretKey == "" {
		p.WGSecretKey = strings.TrimSpace(q.Get("privatekey"))
	}
	if p.WGSecretKey == "" {
		p.WGSecretKey = strings.TrimSpace(q.Get("secretkey"))
	}
	p.WGPublicKey = strings.TrimSpace(q.Get("publickey"))
	p.WGPresharedKey = strings.TrimSpace(q.Get("presharedkey"))
	addrVal := q.Get("address")
	if addrVal == "" {
		addrVal = q.Get("addresses")
	}
	if addrVal == "" {
		addrVal = q.Get("clientip")
	}
	p.WGAddress = genySplitCSV(addrVal)
	allowedIPs := q.Get("allowedips")
	if allowedIPs == "" {
		allowedIPs = q.Get("allowedip")
	}
	p.WGAllowedIPs = genySplitCSV(allowedIPs)
	p.WGReserved = genySplitCSV(q.Get("reserved"))
	dnsVal := q.Get("dns")
	if dnsVal == "" {
		dnsVal = q.Get("dnss")
	}
	p.WGDNS = genySplitCSV(dnsVal)
	if mtu, e := strconv.Atoi(q.Get("mtu")); e == nil && mtu > 0 {
		p.WGMTU = mtu
	}
	kaStr := q.Get("persistentkeepalive")
	if kaStr == "" {
		kaStr = q.Get("keepalive")
	}
	if ka, e := strconv.Atoi(kaStr); e == nil && ka >= 0 {
		p.WGPersistentKeepalive = ka
	}
	if !p.isValid() {
		return nil, fmt.Errorf("geny_link_parser: wireguard: missing required fields")
	}
	return p, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// WireGuard INI config  ([Interface] + [Peer])
// ─────────────────────────────────────────────────────────────────────────────

func (lp *GenyLinkParser) parseWireguardConfig(rawConfig string) (*GenyServerProfile, error) {
	type section int
	const (
		secNone section = iota
		secInterface
		secPeer
	)
	iface := map[string]string{}
	peer := map[string]string{}
	cur := secNone

	for _, line := range strings.Split(rawConfig, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			switch strings.ToLower(line[1 : len(line)-1]) {
			case "interface":
				cur = secInterface
			case "peer":
				cur = secPeer
			default:
				cur = secNone
			}
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if key == "" || val == "" {
			continue
		}
		switch cur {
		case secInterface:
			iface[key] = val
		case secPeer:
			if _, ok := peer[key]; !ok {
				peer[key] = val
			}
		}
	}
	if _, ok := iface["privatekey"]; !ok {
		return nil, fmt.Errorf("geny_link_parser: wg-config: missing Interface.PrivateKey")
	}
	if _, ok := peer["publickey"]; !ok {
		return nil, fmt.Errorf("geny_link_parser: wg-config: missing Peer.PublicKey")
	}
	if _, ok := peer["endpoint"]; !ok {
		return nil, fmt.Errorf("geny_link_parser: wg-config: missing Peer.Endpoint")
	}
	host, port, err := parseGenyEndpointHostPort(peer["endpoint"])
	if err != nil {
		return nil, fmt.Errorf("geny_link_parser: wg-config: invalid Peer.Endpoint")
	}
	p := &GenyServerProfile{
		Protocol:       "wireguard",
		Network:        "wireguard",
		Security:       "none",
		Encryption:     "none",
		OriginalLink:   rawConfig,
		Address:        host,
		Port:           port,
		WGSecretKey:    strings.TrimSpace(iface["privatekey"]),
		WGPublicKey:    strings.TrimSpace(peer["publickey"]),
		WGPresharedKey: strings.TrimSpace(peer["presharedkey"]),
		WGAddress:      genySplitCSV(iface["address"]),
		WGAllowedIPs:   genySplitCSV(peer["allowedips"]),
		WGDNS:          genySplitCSV(iface["dns"]),
		WGReserved:     genySplitCSV(iface["reserved"]),
	}
	if mtu, e := strconv.Atoi(iface["mtu"]); e == nil && mtu > 0 {
		p.WGMTU = mtu
	}
	if ka, e := strconv.Atoi(peer["persistentkeepalive"]); e == nil && ka >= 0 {
		p.WGPersistentKeepalive = ka
	}
	p.Name = strings.TrimSpace(iface["name"])
	if p.Name == "" {
		p.Name = "WireGuard " + p.Address
	}
	if !p.isValid() {
		return nil, fmt.Errorf("geny_link_parser: wg-config: missing required fields")
	}
	return p, nil
}

// parseGenyEndpointHostPort splits "host:port" or "[ipv6]:port".
func parseGenyEndpointHostPort(ep string) (host string, port uint16, err error) {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return "", 0, fmt.Errorf("empty endpoint")
	}
	if strings.HasPrefix(ep, "[") {
		close := strings.Index(ep, "]")
		if close <= 1 || close+2 > len(ep) || ep[close+1] != ':' {
			return "", 0, fmt.Errorf("invalid IPv6 endpoint %q", ep)
		}
		h := ep[1:close]
		p, ok := genyParsePortStr(ep[close+2:])
		if !ok {
			return "", 0, fmt.Errorf("invalid port in %q", ep)
		}
		return h, p, nil
	}
	last := strings.LastIndex(ep, ":")
	if last <= 0 || last == len(ep)-1 {
		return "", 0, fmt.Errorf("invalid endpoint %q", ep)
	}
	h := ep[:last]
	p, ok := genyParsePortStr(ep[last+1:])
	if !ok {
		return "", 0, fmt.Errorf("invalid port in %q", ep)
	}
	return h, p, nil
}
