package proxyconfig

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Reasons for classifying and dropping proxy lines.
const (
	ReasonUnparsable    = "unparsable"
	ReasonInvalidPort   = "invalid_port"
	ReasonInvalidUUID   = "invalid_uuid"
	ReasonUnroutable    = "unroutable_server"
	ReasonInvalidServer = "invalid_server"
	ReasonDummy         = "dummy"
)

// AllDropReasons is the complete list of rejection reasons for metrics and reporting.
var AllDropReasons = []string{
	ReasonUnparsable,
	ReasonInvalidPort,
	ReasonInvalidUUID,
	ReasonUnroutable,
	ReasonInvalidServer,
	ReasonDummy,
}

var dummyIndicators = []string{
	"00000000-0000-0000-0000-000000000000",
	"app%20not%20supported",
	"app not supported",
	"proxies: []",
}

var uuidProtocols = map[string]bool{
	"vless": true,
	"vmess": true,
	"tuic":  true,
}

var insecureSchemes = map[string]bool{
	"hysteria2": true,
	"hy2":       true,
	"tuic":      true,
}

var identityParams = map[string]bool{
	"security":           true,
	"sni":                true,
	"pbk":                true,
	"sid":                true,
	"host":               true,
	"path":               true,
	"servicename":        true,
	"flow":               true,
	"type":               true,
	"headertype":         true,
	"encryption":         true,
	"mode":               true,
	"alpn":               true,
	"extra":              true,
	"obfs":               true,
	"obfs-password":      true,
	"obfspassword":       true,
	"congestion_control": true,
	"congestion":         true,
	"publickey":          true,
	"presharedkey":       true,
	"address":            true,
}

var caseSensitiveParams = map[string]bool{
	"path":          true,
	"servicename":   true,
	"pbk":           true,
	"publickey":     true,
	"presharedkey":  true,
	"obfs-password": true,
	"obfspassword":  true,
}

// FilterResult holds the aggregated outcome of the L0/L1 filtering pipeline.
type FilterResult struct {
	Kept            []string
	Endpoints       []string
	EndpointToLines map[string][]int
	LineEndpoint    []string
	Dropped         map[string]int
	Stats           FilterStats
}

// FilterStats holds summary metrics for telemetry and dashboard reporting.
type FilterStats struct {
	Input           int     `json:"input"`
	Kept            int     `json:"kept"`
	Dropped         int     `json:"dropped"`
	EndpointsUnique int     `json:"endpoints_unique"`
	HostsUnique     int     `json:"hosts_unique"`
	RemovalPct      float64 `json:"removal_pct"`
	DedupSavingPct  float64 `json:"dedup_saving_pct"`
}

// IsDummyProxy reports whether the raw proxy string matches known placeholder / bogus values.
func IsDummyProxy(rawLine string) bool {
	if rawLine == "" {
		return false
	}
	lower := strings.ToLower(rawLine)
	for _, ind := range dummyIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// IsInvalidPort checks if a port integer is outside 1..=65535.
func IsInvalidPort(port int) bool {
	return port <= 0 || port > 65535
}

// IsUnroutableServer checks if an IP address is loopback, unspecified, multicast, reserved, or link-local.
func IsUnroutableServer(host string) bool {
	clean := strings.Trim(strings.Trim(strings.TrimSpace(host), "["), "]")
	if clean == "" {
		return true
	}
	ip := net.ParseIP(clean)
	if ip == nil {
		return false // It's a hostname, not an IP
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}
	// Check IPv4 reserved 240.0.0.0/4
	if v4 := ip.To4(); v4 != nil {
		if v4[0] >= 240 {
			return true
		}
	}
	return false
}

// IsStructurallyInvalidServer validates if host can structurally represent an IP or public domain.
func IsStructurallyInvalidServer(host string) bool {
	clean := strings.TrimSpace(host)
	if clean == "" {
		return true
	}
	rawIP := strings.Trim(strings.Trim(clean, "["), "]")
	if net.ParseIP(rawIP) != nil {
		return false
	}
	if strings.ContainsAny(clean, "/?#@\\:") || strings.Contains(clean, "://") {
		return true
	}
	for _, r := range clean {
		if unicode.IsSpace(r) {
			return true
		}
	}
	if !strings.Contains(clean, ".") {
		return true // single-label name cannot resolve publicly
	}
	if len(clean) > 253 {
		return true
	}
	stripped := strings.TrimSuffix(clean, ".")
	labels := strings.Split(stripped, ".")
	for _, lab := range labels {
		if len(lab) == 0 || len(lab) > 63 {
			return true
		}
		if strings.HasPrefix(lab, "-") || strings.HasSuffix(lab, "-") {
			return true
		}
		for _, ch := range lab {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return true
			}
		}
	}
	return false
}

// IsInvalidUUID validates user ID per Xray specification.
func IsInvalidUUID(uuid, proto string) bool {
	protoLower := strings.ToLower(strings.TrimSpace(proto))
	if !uuidProtocols[protoLower] {
		return false // Arbitrary passwords allowed for shadowsocks/trojan
	}
	s := strings.TrimSpace(uuid)
	if s == "" {
		return true
	}
	hexOnly := strings.ReplaceAll(s, "-", "")
	if len(hexOnly) == 32 {
		allHex := true
		allZero := true
		for _, c := range hexOnly {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				allHex = false
				break
			}
			if c != '0' {
				allZero = false
			}
		}
		if allHex {
			return allZero // nil UUID is invalid
		}
	}
	return len([]byte(s)) >= 30
}

// IsPlausibleFrontingHost checks whether host can serve as a plausible CDN/SNI fronting authority.
func IsPlausibleFrontingHost(host string) bool {
	s := strings.TrimSpace(host)
	if s == "" || len(s) > 253 {
		return false
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") && len(s) > 2 {
		return true
	}
	badChars := " \t\r\n/:@?#{}\"\\,;|<>()[]"
	if strings.ContainsAny(s, badChars) {
		return false
	}
	trimmed := strings.TrimSuffix(s, ".")
	if trimmed == "" || strings.Contains(trimmed, "..") || !strings.Contains(trimmed, ".") {
		return false
	}
	for _, lab := range strings.Split(trimmed, ".") {
		if len(lab) == 0 || len(lab) > 63 {
			return false
		}
		if strings.HasPrefix(lab, "-") || strings.HasSuffix(lab, "-") {
			return false
		}
		for _, ch := range lab {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return false
			}
		}
	}
	return true
}

func decodeForgivingBase64(input string) ([]byte, bool) {
	clean := strings.TrimSpace(input)
	if clean == "" {
		return nil, false
	}
	if b, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return b, true
	}
	padded := clean
	switch len(clean) % 4 {
	case 2:
		padded += "=="
	case 3:
		padded += "="
	}
	if b, err := base64.StdEncoding.DecodeString(padded); err == nil {
		return b, true
	}
	urlClean := strings.ReplaceAll(strings.ReplaceAll(clean, "-", "+"), "_", "/")
	switch len(urlClean) % 4 {
	case 2:
		urlClean += "=="
	case 3:
		urlClean += "="
	}
	if b, err := base64.StdEncoding.DecodeString(urlClean); err == nil {
		return b, true
	}
	return nil, false
}

// ClassifyProxy evaluates a raw proxy line, returning (reason, false) if invalid, or ("", true) if valid.
func ClassifyProxy(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ReasonUnparsable, false
	}
	if IsDummyProxy(trimmed) {
		return ReasonDummy, false
	}

	withoutRemark := strings.SplitN(trimmed, "#", 2)[0]
	u, err := url.Parse(withoutRemark)
	if err != nil {
		return ReasonUnparsable, false
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "vmess" {
		b64 := strings.TrimPrefix(withoutRemark, "vmess://")
		b, ok := decodeForgivingBase64(b64)
		if !ok {
			return ReasonUnparsable, false
		}
		var obj map[string]interface{}
		if err := json.Unmarshal(b, &obj); err != nil {
			return ReasonUnparsable, false
		}
		portStr := fmt.Sprintf("%v", obj["port"])
		port, err := strconv.Atoi(portStr)
		if err != nil || IsInvalidPort(port) {
			return ReasonInvalidPort, false
		}
		server := fmt.Sprintf("%v", obj["add"])
		if IsStructurallyInvalidServer(server) {
			return ReasonInvalidServer, false
		}
		if IsUnroutableServer(server) {
			return ReasonUnroutable, false
		}
		uuid := fmt.Sprintf("%v", obj["id"])
		if IsInvalidUUID(uuid, "vmess") {
			return ReasonInvalidUUID, false
		}
		return "", true
	}

	host := u.Hostname()
	portStr := u.Port()
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || IsInvalidPort(port) {
			return ReasonInvalidPort, false
		}
	} else if scheme != "ss" {
		return ReasonInvalidPort, false
	}

	if host != "" {
		if IsStructurallyInvalidServer(host) {
			return ReasonInvalidServer, false
		}
		if IsUnroutableServer(host) {
			return ReasonUnroutable, false
		}
	}

	if u.User != nil {
		user := u.User.Username()
		if IsInvalidUUID(user, scheme) {
			return ReasonInvalidUUID, false
		}
	}

	return "", true
}

// ComputeNodeDedupKey computes the deterministic CDN-aware deduplication identity fingerprint.
func ComputeNodeDedupKey(line string) string {
	raw := strings.TrimSpace(line)
	if raw == "" {
		return ""
	}

	if strings.HasPrefix(raw, "vmess://") {
		withoutPrefix := strings.TrimPrefix(raw, "vmess://")
		b64 := strings.SplitN(withoutPrefix, "#", 2)[0]
		if b, ok := decodeForgivingBase64(b64); ok {
			var obj map[string]interface{}
			if err := json.Unmarshal(b, &obj); err == nil {
				add := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", obj["add"])))
				rawHost := fmt.Sprintf("%v", obj["host"])
				if rawHost == "<nil>" {
					rawHost = ""
				}
				rawSni := fmt.Sprintf("%v", obj["sni"])
				if rawSni == "<nil>" {
					rawSni = ""
				}
				rawTLS := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", obj["tls"])))
				tls := ""
				if rawTLS == "tls" || rawTLS == "reality" || rawTLS == "xtls" {
					tls = rawTLS
				}
				rawNet := fmt.Sprintf("%v", obj["net"])
				netType := strings.ToLower(strings.TrimSpace(rawNet))
				if netType == "" || netType == "raw" || netType == "none" || netType == "tcp" {
					netType = "tcp"
				}
				rawPath := fmt.Sprintf("%v", obj["path"])
				path := rawPath
				if path == "" || path == "<nil>" {
					path = "/"
				}

				host := strings.ToLower(strings.TrimSpace(rawHost))
				sni := strings.ToLower(strings.TrimSpace(rawSni))
				if host != "" && !IsPlausibleFrontingHost(host) {
					host = ""
				}
				if sni != "" && !(IsPlausibleFrontingHost(sni) && tls == "tls") {
					sni = ""
				}

				fallbackSrv := rawSni
				if fallbackSrv == "" || fallbackSrv == "<nil>" {
					fallbackSrv = rawHost
				}
				srv := strings.ToLower(strings.TrimSpace(fallbackSrv))
				if srv != "" && srv != "<nil>" && !IsPlausibleFrontingHost(srv) {
					srv = ""
				}

				fronting := host
				if sni != "" {
					fronting = fmt.Sprintf("%s~%s", host, sni)
				}

				port := fmt.Sprintf("%v", obj["port"])
				id := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", obj["id"])))
				aid := "0"
				if rawAid, ok := obj["aid"]; ok {
					if n, err := strconv.Atoi(fmt.Sprintf("%v", rawAid)); err == nil {
						aid = strconv.Itoa(n)
					}
				}
				scy := "auto"
				if rawScy, ok := obj["scy"]; ok && fmt.Sprintf("%v", rawScy) != "" && fmt.Sprintf("%v", rawScy) != "<nil>" {
					scy = fmt.Sprintf("%v", rawScy)
				}

				return fmt.Sprintf("vmess:%s|ep=%s:%s:%s:%s:%s:%s:%s:%s:srv=%s",
					add, fronting, port, id, netType, path, tls, aid, scy, srv)
			}
		}
		return strings.SplitN(raw, "#", 2)[0]
	}

	if strings.HasPrefix(raw, "ss://") {
		withoutRemark := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(raw, "ss://"), "#", 2)[0])
		authority := strings.SplitN(withoutRemark, "?", 2)[0]
		if strings.Contains(authority, "@") {
			parts := strings.SplitN(authority, "@", 2)
			userinfo := parts[0]
			hostpart := strings.SplitN(parts[1], "/", 2)[0]
			if b, ok := decodeForgivingBase64(userinfo); ok {
				if strings.Contains(string(b), ":") {
					userinfo = string(b)
				}
			}
			userinfoClean := strings.ToLower(userinfo)
			hpParts := strings.SplitN(hostpart, ":", 2)
			if len(hpParts) == 2 {
				return fmt.Sprintf("ss:sip002:%s@%s:%s", userinfoClean, strings.ToLower(hpParts[0]), hpParts[1])
			}
		}
		return fmt.Sprintf("ss:legacy:%s", strings.ToLower(withoutRemark))
	}

	withoutRemark := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
	u, err := url.Parse(withoutRemark)
	if err != nil {
		if len(withoutRemark) > 200 {
			return withoutRemark[:200]
		}
		return withoutRemark
	}

	scheme := strings.ToLower(u.Scheme)
	q := u.Query()
	meaningful := make(map[string]string)

	for k, vals := range q {
		kLower := strings.ToLower(strings.TrimSpace(k))
		if !identityParams[kLower] || len(vals) == 0 {
			continue
		}
		val := vals[0]
		if !caseSensitiveParams[kLower] {
			val = strings.ToLower(strings.TrimSpace(val))
		}
		if kLower == "type" {
			if val == "" || val == "raw" || val == "none" || val == "tcp" {
				val = ""
			}
		}
		if kLower == "security" || kLower == "encryption" || kLower == "headertype" {
			if val == "none" {
				val = ""
			}
		}
		if val != "" {
			meaningful[kLower] = val
		}
	}

	if insecureSchemes[scheme] {
		insec := "0"
		for _, ik := range []string{"insecure", "allowInsecure", "allow_insecure"} {
			v := strings.ToLower(strings.TrimSpace(q.Get(ik)))
			if v == "1" || v == "true" || v == "yes" || v == "on" {
				insec = "1"
				break
			}
		}
		meaningful["insecure"] = insec
	}

	sniVal := meaningful["sni"]
	hostVal := meaningful["host"]
	secVal := meaningful["security"]

	if sniVal != "" && !IsPlausibleFrontingHost(sniVal) {
		sniVal = ""
		delete(meaningful, "sni")
	} else if sniVal != "" && secVal != "tls" {
		sniVal = ""
	}

	if hostVal != "" && !IsPlausibleFrontingHost(hostVal) {
		hostVal = ""
		delete(meaningful, "host")
	}

	endpoint := sniVal
	if endpoint == "" {
		endpoint = hostVal
	}

	var qPairs []string
	for k, v := range meaningful {
		qPairs = append(qPairs, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(qPairs)
	sortedQuery := strings.Join(qPairs, "&")

	user := ""
	pass := ""
	if u.User != nil {
		user = strings.ToLower(u.User.Username())
		if p, has := u.User.Password(); has {
			pass = strings.ToLower(p)
		}
	}

	host := strings.ToLower(u.Hostname())
	port := u.Port()
	path := strings.TrimSuffix(u.Path, "/")

	return fmt.Sprintf("%s:%s:%s@%s|ep=%s:%s%s?%s",
		scheme, user, pass, host, endpoint, port, path, sortedQuery)
}

// ComputeStableTag returns a deterministic 6-character hex tag from the proxy dedup key.
func ComputeStableTag(line string) string {
	key := ComputeNodeDedupKey(line)
	sum := sha256.Sum256([]byte(key))
	hexStr := hex.EncodeToString(sum[:])
	return strings.ToUpper(hexStr[:6])
}

// FilterProxyLines runs L0 deduplication and L1 structural validation on input lines.
func FilterProxyLines(lines []string) FilterResult {
	kept := make([]string, 0)
	endpoints := make([]string, 0)
	epIndex := make(map[string]int)
	epToLines := make(map[string][]int)
	lineEndpoint := make([]string, 0)
	dropped := make(map[string]int)
	for _, r := range AllDropReasons {
		dropped[r] = 0
	}

	total := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		total++

		reason, ok := ClassifyProxy(line)
		if !ok {
			dropped[reason]++
			continue
		}

		key := ComputeNodeDedupKey(line)
		ep := key
		if ep == "" {
			dropped[ReasonInvalidServer]++
			continue
		}

		idx := len(kept)
		kept = append(kept, line)
		lineEndpoint = append(lineEndpoint, ep)

		if _, exists := epIndex[ep]; !exists {
			epIndex[ep] = len(endpoints)
			endpoints = append(endpoints, ep)
			epToLines[ep] = make([]int, 0)
		}
		epToLines[ep] = append(epToLines[ep], idx)
	}

	droppedTotal := 0
	for _, cnt := range dropped {
		droppedTotal += cnt
	}

	remPct := 0.0
	if total > 0 {
		remPct = float64(droppedTotal) * 100.0 / float64(total)
	}
	dedupPct := 0.0
	if len(kept) > 0 {
		dedupPct = (1.0 - float64(len(endpoints))/float64(len(kept))) * 100.0
	}

	return FilterResult{
		Kept:            kept,
		Endpoints:       endpoints,
		EndpointToLines: epToLines,
		LineEndpoint:    lineEndpoint,
		Dropped:         dropped,
		Stats: FilterStats{
			Input:           total,
			Kept:            len(kept),
			Dropped:         droppedTotal,
			EndpointsUnique: len(endpoints),
			HostsUnique:     len(endpoints),
			RemovalPct:      remPct,
			DedupSavingPct:  dedupPct,
		},
	}
}

// CountryCodeToFlag converts an ISO 3166-1 alpha-2 code to an Emoji flag.
func CountryCodeToFlag(countryCode string) string {
	cc := strings.ToUpper(strings.TrimSpace(countryCode))
	if len(cc) != 2 {
		return ""
	}
	r1 := rune(0x1F1E6 + int(cc[0]-'A'))
	r2 := rune(0x1F1E6 + int(cc[1]-'A'))
	return string([]rune{r1, r2})
}
