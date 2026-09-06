package redact

import (
	"strings"
	"testing"
)

func TestRedactString(t *testing.T) {
	tests := []struct {
		input    string
		contains []string // Substrings that MUST still be present (e.g. key name, schema)
		excludes []string // Substrings that MUST NOT be present (the actual secrets)
	}{
		{
			input:    "api_key=secret-key-123",
			contains: []string{"api_key="},
			excludes: []string{"secret-key-123"},
		},
		{
			input:    "token=12345-abcde&username=test",
			contains: []string{"token=", "username=test"},
			excludes: []string{"12345-abcde"},
		},
		{
			input:    "Authorization: Bearer myBearerToken123",
			contains: []string{"Authorization: Bearer"},
			excludes: []string{"myBearerToken123"},
		},
		{
			input:    "connecting to vless://e3b8a1c9-7d84-48a0-97b6-123456789abc@127.0.0.1:8443?security=xtls",
			contains: []string{"connecting to vless", "127.0.0.1:8443"},
			excludes: []string{"e3b8a1c9-7d84-48a0-97b6-123456789abc"},
		},
		{
			input:    "trojan://supersecretpassword@trojan.covert.net:443",
			contains: []string{"trojan", "trojan.covert.net:443"},
			excludes: []string{"supersecretpassword"},
		},
		{
			input:    "{\\\"token\\\":\\\"escaped-json-secret\\\"}",
			contains: []string{"\\\"token\\\":\\\"***"},
			excludes: []string{"escaped-json-secret"},
		},
		{
			input:    `{"token":"json-secret"}`,
			contains: []string{`"token":"***`},
			excludes: []string{"json-secret"},
		},
		{
			input:    "https://example.test/callback?token%3Dpercent%2Dencoded%2Dsecret&state=ok",
			contains: []string{"token%3D***", "state=ok"},
			excludes: []string{"percent%2Dencoded%2Dsecret"},
		},
	}

	for _, tc := range tests {
		got := String(tc.input)
		for _, match := range tc.contains {
			if !strings.Contains(got, match) {
				t.Errorf("expected redacted output %q to contain %q", got, match)
			}
		}
		for _, avoid := range tc.excludes {
			if strings.Contains(got, avoid) {
				t.Errorf("redaction failed: output %q still contains secret %q", got, avoid)
			}
		}
	}
}
