package provision

import (
	"encoding/json"
	"fmt"
	"strings"
)

type cloudflareAPIErrorEnvelope struct {
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

func formatCloudflareAPIError(statusCode int, body []byte, retryAfter string) error {
	detail := strings.TrimSpace(string(body))
	var envelope cloudflareAPIErrorEnvelope
	if json.Unmarshal(body, &envelope) == nil && len(envelope.Errors) > 0 {
		parts := make([]string, 0, len(envelope.Errors))
		for _, entry := range envelope.Errors {
			message := strings.TrimSpace(entry.Message)
			if message == "" {
				message = "unknown Cloudflare error"
			}
			if entry.Code != 0 {
				message = fmt.Sprintf("%s (code %d)", message, entry.Code)
			}
			parts = append(parts, message)
		}
		detail = strings.Join(parts, "; ")
	}
	if detail == "" {
		detail = "empty response body"
	}
	if wait := strings.TrimSpace(retryAfter); wait != "" {
		detail += fmt.Sprintf("; Retry-After: %s", wait)
	}
	return fmt.Errorf("HTTP error %d: %s", statusCode, detail)
}
