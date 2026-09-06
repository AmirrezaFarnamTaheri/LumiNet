package diagnostics

import (
	"bytes"
	"strings"
)

// AntiBotDetector analyzes HTTP responses for CDN bot-blocking headers or html patterns.
type AntiBotDetector struct{}

// BotBlockStatus holds detection results.
type BotBlockStatus struct {
	IsBotBlocked bool   `json:"is_bot_blocked"`
	CDNProvider  string `json:"cdn_provider"`
	Reason       string `json:"reason"`
}

// NewAntiBotDetector creates a new AntiBotDetector instance.
func NewAntiBotDetector() *AntiBotDetector {
	return &AntiBotDetector{}
}

// InspectResponse checks response headers and body for Cloudflare/Akamai anti-bot signatures.
func (d *AntiBotDetector) InspectResponse(statusCode int, headers map[string][]string, body []byte) BotBlockStatus {
	// 1. Cloudflare Turnstile / Challenge check
	if statusCode == 403 || statusCode == 503 {
		serverHeader := getHeader(headers, "Server")
		if strings.Contains(strings.ToLower(serverHeader), "cloudflare") {
			if bytes.Contains(body, []byte("Just a moment...")) || bytes.Contains(body, []byte("cf-mitigation")) || bytes.Contains(body, []byte("turnstile")) {
				return BotBlockStatus{
					IsBotBlocked: true,
					CDNProvider:  "Cloudflare",
					Reason:       "Cloudflare Turnstile Challenge Detected",
				}
			}
		}

		// 2. Akamai Access Denied check
		if strings.Contains(strings.ToLower(serverHeader), "akamaighost") || bytes.Contains(body, []byte("errors.edgesuite.net")) {
			return BotBlockStatus{
				IsBotBlocked: true,
				CDNProvider:  "Akamai",
				Reason:       "Akamai Edge Block Detected",
			}
		}

		// 3. ArvanCloud JavaScript Challenge check
		if bytes.Contains(body, []byte("__arcsjs")) && bytes.Contains(body, []byte("__arcsjsc")) {
			return BotBlockStatus{
				IsBotBlocked: true,
				CDNProvider:  "ArvanCloud",
				Reason:       "ArvanCloud JavaScript Challenge Detected",
			}
		}
	}

	return BotBlockStatus{IsBotBlocked: false}
}

func getHeader(headers map[string][]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(k, key) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
