// Package redact provides secret masking for logs and error messages.
//
// Addresses S-09: Redact Enhancement.
//
// All log output and error strings that may contain user secrets MUST pass
// through one of the functions in this package before reaching disk or the
// frontend.  The package is intentionally allocation-light: rules are
// compiled once at init time and reused across calls.
package redact

import (
	"log/slog"
	"regexp"
)

// redactRule pairs a compiled regex with its replacement template.
type redactRule struct {
	pattern     *regexp.Regexp
	replacement string
}

var rules = []redactRule{
	// Structured JSON payloads commonly reach logs after an upstream error or
	// telemetry serialization. Handle them before generic key=value rules.
	{
		pattern:     regexp.MustCompile(`(?i)("(?:api[_-]?key|token|secret|password|pass|auth|credential)"\s*:\s*")[^"]*`),
		replacement: `${1}***`,
	},
	// The same form after one JSON escaping pass, for example a JSON body held
	// inside an error string.
	{
		pattern:     regexp.MustCompile(`(?i)(\\"(?:api[_-]?key|token|secret|password|pass|auth|credential)\\"\s*:\s*\\")[^\\"]*`),
		replacement: `${1}***`,
	},
	// URL-encoded query strings are not matched by the ordinary '=' rule.
	{
		pattern:     regexp.MustCompile(`(?i)(api(?:%5[fF]|[_-])?key|token|secret|password|pass|auth|credential)(%3[dD])([^&\s]+)`),
		replacement: `${1}${2}***`,
	},
	// Pattern 1: key=value query parameters (api_key=xxx, token=xxx, etc.)
	{
		pattern:     regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|pass|auth|credential)=([^&\s]+)`),
		replacement: `$1=***`,
	},
	// Pattern 2: Bearer tokens in Authorization headers
	{
		pattern:     regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+`),
		replacement: `${1}***`,
	},
	// Pattern 3: Proxy subscription URIs (vless://secret@host, vmess://..., etc.)
	{
		pattern:     regexp.MustCompile(`(?i)(vless|vmess|trojan|ss|hysteria2?|tuic|naive|wireguard)://[^@\s]+@`),
		replacement: `${1}://***@`,
	},
	// Pattern 4: WireGuard private/public keys (base64, 44 chars)
	{
		pattern:     regexp.MustCompile(`(?i)(private[_-]?key|PrivateKey)\s*[=:]\s*[A-Za-z0-9+/]{43}=`),
		replacement: `${1}=***`,
	},
	// Pattern 5: PEM private key headers
	{
		pattern:     regexp.MustCompile(`-----BEGIN\s+(RSA|EC|OPENSSH|PRIVATE)\s+PRIVATE KEY-----[\s\S]*?-----END[^-]+-----`),
		replacement: `-----BEGIN PRIVATE KEY----- *** (redacted) *** -----END PRIVATE KEY-----`,
	},
	// Pattern 6: Email addresses
	{
		pattern:     regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		replacement: `***@***.***`,
	},
	// Pattern 7: IPv4 addresses in internal ranges (RFC1918) — redact if present
	// in proxy-related contexts (not DNS responses, etc.)
	{
		pattern:     regexp.MustCompile(`(?i)(node_ip|server_ip|peer_ip)\s*[=:]\s*(\d{1,3}\.){3}\d{1,3}`),
		replacement: `${1}=***.***.***.***`,
	},
	// Pattern 8: Hex API keys / secrets (32–64 hex chars)
	{
		pattern:     regexp.MustCompile(`(?i)(key|secret|token)\s*[=:]\s*[0-9a-fA-F]{32,64}`),
		replacement: `${1}=***`,
	},
	// Pattern 9: DDNS credential tokens (duckdns, cloudflare, dynu, etc.)
	{
		pattern:     regexp.MustCompile(`(?i)(ddns[_-]?token|duckdns[_-]?token|cf[_-]?api[_-]?key|dynu[_-]?password)\s*[=:]\s*\S+`),
		replacement: `${1}=***`,
	},
	// Pattern 10: 2Captcha / captcha API keys
	{
		pattern:     regexp.MustCompile(`(?i)(2captcha[_-]?key|captcha[_-]?api[_-]?key)\s*[=:]\s*\S+`),
		replacement: `${1}=***`,
	},
}

// String returns the redacted version of the given string, masking any secrets.
func String(s string) string {
	out := s
	for _, r := range rules {
		out = r.pattern.ReplaceAllString(out, r.replacement)
	}
	return out
}

// Bytes redacts secrets in a byte slice and returns a new slice.
func Bytes(b []byte) []byte {
	return []byte(String(string(b)))
}

// SlogAttr returns an slog.Attr whose string value has been redacted.
// Use instead of slog.String for potentially sensitive fields.
func SlogAttr(key, value string) slog.Attr {
	return slog.String(key, String(value))
}

// SlogErr returns an slog.Attr for an error with the message redacted.
func SlogErr(err error) slog.Attr {
	if err == nil {
		return slog.String("err", "<nil>")
	}
	return slog.String("err", String(err.Error()))
}

// Redactable is implemented by types that can produce their own
// redacted string representation.
type Redactable interface {
	Redact() string
}

// Value redacts any type: if it implements Redactable, calls Redact();
// otherwise passes fmt.Sprint(v) through String().
func Value(v any) string {
	if r, ok := v.(Redactable); ok {
		return r.Redact()
	}
	return String(defaultSprint(v))
}

// defaultSprint converts a value to string without importing fmt.
func defaultSprint(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case error:
		return t.Error()
	default:
		return "<redact: unsupported type>"
	}
}
