// DNS-tunnel share-link parsing ;
// grammar re-expressed). Three schemes appear in the wild on operator
// subscription feeds:
//
//	dnstt://<pubkey>@<ns>[:port]?authoritative=false&dns=<resolver-addr>
//	dns://<base64 JSON {addr,ns,user,pass,pubkey}>
//	slipnet://<base64 pipe-record: parts[3]=ns parts[4]="dns1,dns2" parts[11]=pubkey>
package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// DNSTunnelConfig is the normalised form of one share link.
type DNSTunnelConfig struct {
	Scheme string  `json:"scheme"`
	SubKey string  `json:"sub_key,omitempty"`
	Addr   string  `json:"addr"`
	NS     string  `json:"ns"`
	PubKey *string `json:"pub_key,omitempty"`
	User   *string `json:"user,omitempty"`
	Pass   *string `json:"pass,omitempty"`
}

// ParseDNSShareLine decodes one subscription line whose scheme appears in
// allowedSchemes. Unknown schemes return nil without error so callers can
// skip mixed feeds.
func ParseDNSShareLine(line string, allowedSchemes []string) (*DNSTunnelConfig, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}
	for _, scheme := range allowedSchemes {
		prefix := scheme + "://"
		if !strings.HasPrefix(strings.ToLower(line), strings.ToLower(prefix)) {
			continue
		}
		switch scheme {
		case "dnstt":
			return parseDNSTTShare(line)
		case "slipnet":
			return parseSlipnetShare(line)
		case "dns":
			return parseDNSScheme(line)
		default:
			return nil, fmt.Errorf("unsupported dns-tunnel scheme %q", scheme)
		}
	}
	return nil, nil
}

// ParseDNSShareContent splits a fetched subscription body and decodes every
// recognised line. Unrecognised lines are skipped silently (mixed feeds).
func ParseDNSShareContent(content string, allowedSchemes []string) []DNSTunnelConfig {
	var out []DNSTunnelConfig
	for _, line := range strings.Split(content, "\n") {
		cfg, err := ParseDNSShareLine(line, allowedSchemes)
		if err != nil || cfg == nil {
			continue
		}
		out = append(out, *cfg)
	}
	return out
}

// parseDNSTTShare handles both the plain URL form and (upstream quirk) the
// base64-wrapped form that still decodes back to the same URL.
func parseDNSTTShare(line string) (*DNSTunnelConfig, error) {
	if decoded, err := decodeFlexibleB64(strings.TrimPrefix(line, "dnstt://")); err == nil {
		if looksLikeURL(decoded) && strings.HasPrefix(decoded, "dnstt://") {
			line = decoded
		}
	}
	parsed, err := url.Parse(line)
	if err != nil {
		return nil, fmt.Errorf("dnstt url: %w", err)
	}
	cfg := &DNSTunnelConfig{Scheme: "dnstt"}
	if user := parsed.User; user != nil {
		pub := user.Username()
		cfg.PubKey = strPtr(pub)
	}
	host := parsed.Hostname()
	if port := parsed.Port(); port != "" {
		host = host + ":" + port
	}
	cfg.NS = trimTrailingDot(host)
	q := parsed.Query()
	cfg.Addr = q.Get("dns")
	if authoritative(q.Get("authoritative")) {
		cfg.User = strPtr(q.Get("user"))
		cfg.Pass = strPtr(q.Get("pass"))
	}
	if cfg.Addr == "" {
		return nil, fmt.Errorf("dnstt share missing dns= resolver address")
	}
	return cfg, nil
}

// parseSlipnetShare decodes the base64 pipe-record emitted by slipnet clients:
// index 3 carries the authoritative NS, index 4 a comma-separated resolver
// list (first entry wins as addr), index 11 the optional public key.
func parseSlipnetShare(line string) (*DNSTunnelConfig, error) {
	decoded, err := decodeFlexibleB64(strings.TrimPrefix(line, "slipnet://"))
	if err != nil {
		return nil, fmt.Errorf("slipnet base64: %w", err)
	}
	parts := strings.Split(decoded, "|")
	if len(parts) < 12 {
		return nil, fmt.Errorf("slipnet record has %d fields, need >= 12", len(parts))
	}
	ns := trimTrailingDot(parts[3])
	addr := strings.TrimSuffix(strings.Split(parts[4], ",")[0], ":0")
	cfg := &DNSTunnelConfig{Scheme: "slipnet", NS: ns, Addr: addr}
	if parts[11] != "" {
		cfg.PubKey = strPtr(parts[11])
	}
	if cfg.Addr == "" || cfg.NS == "" {
		return nil, fmt.Errorf("slipnet record missing ns or addr")
	}
	return cfg, nil
}

// parseDNSScheme decodes base64 JSON: {"addr","ns","user","pass","pubkey"}.
func parseDNSScheme(line string) (*DNSTunnelConfig, error) {
	decoded, err := decodeFlexibleB64(strings.TrimPrefix(line, "dns://"))
	if err != nil {
		return nil, fmt.Errorf("dns base64: %w", err)
	}
	var doc struct {
		Addr   string `json:"addr"`
		NS     string `json:"ns"`
		User   string `json:"user"`
		Pass   string `json:"pass"`
		PubKey string `json:"pubkey"`
	}
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, fmt.Errorf("dns payload not JSON: %w", err)
	}
	cfg := &DNSTunnelConfig{Scheme: "dns", Addr: doc.Addr, NS: trimTrailingDot(doc.NS)}
	if doc.PubKey != "" {
		cfg.PubKey = strPtr(doc.PubKey)
	}
	if doc.User != "" {
		cfg.User = strPtr(doc.User)
	}
	if doc.Pass != "" {
		cfg.Pass = strPtr(doc.Pass)
	}
	if cfg.Addr == "" || cfg.NS == "" {
		return nil, fmt.Errorf("dns record missing addr or ns")
	}
	return cfg, nil
}

// --- helpers ---

func strPtr(s string) *string { return &s }

func trimTrailingDot(s string) string { return strings.TrimSuffix(s, ".") }

func authoritative(flag string) bool { return flag == "true" }

func decodeFlexibleB64(data string) (string, error) {
	clean := strings.TrimSpace(data)
	if raw, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return string(raw), nil
	}
	raw, err := base64.URLEncoding.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("neither std nor url-safe base64")
	}
	return string(raw), nil
}

func looksLikeURL(s string) bool {
	return strings.Contains(s, "://")
}
