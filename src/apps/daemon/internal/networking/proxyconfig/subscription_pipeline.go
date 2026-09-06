package proxyconfig

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ParsedProxyNode represents an extracted proxy node from a subscription payload.
type ParsedProxyNode struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	RawURI   string `json:"raw_uri"`
	Tag      string `json:"tag"`
}

// IngestSubscription decodes and parses raw base64 or plaintext subscription lines.
func IngestSubscription(content string) ([]ParsedProxyNode, error) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return nil, fmt.Errorf("empty subscription content")
	}

	// Try base64 decoding first
	decodedBytes, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil {
		trimmed = string(decodedBytes)
	}

	lines := strings.Split(trimmed, "\n")
	var nodes []ParsedProxyNode
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "://", 2)
		if len(parts) != 2 {
			continue
		}

		protocol := parts[0]
		rest := parts[1]

		// Extract tag if present (e.g. URI#tag)
		tag := ""
		if hashIdx := strings.Index(rest, "#"); hashIdx != -1 {
			tag = rest[hashIdx+1:]
			rest = rest[:hashIdx]
		}

		if seen[line] {
			continue
		}
		seen[line] = true

		nodes = append(nodes, ParsedProxyNode{
			Protocol: protocol,
			Host:     rest,
			Port:     443, // Default fallback
			RawURI:   line,
			Tag:      tag,
		})
	}

	return nodes, nil
}
