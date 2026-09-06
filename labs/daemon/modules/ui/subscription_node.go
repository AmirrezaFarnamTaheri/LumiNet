// Package ui implements admin panel models, wireguard obfuscation, and subscription services.
// Ported from: 3ax-ui-main (sub/subService.go)
// Target path: server/internal/ui/subscription_node.go

package ui

import (
	"encoding/base64"
	"strings"
)

// SubscriptionNode represents a single config profile link node.
type SubscriptionNode struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"` // vless, trojan, vmess, ss, shadowsocks
	URL      string `json:"url"`
}

// Getters & Setters for SubscriptionNode
func (n *SubscriptionNode) GetName() string { return n.Name }
func (n *SubscriptionNode) SetName(v string) { n.Name = v }

// FormatSubscriptionList serializes nodes to standard raw/base64 subscriptions formats.
// Maps to base64 encoding logic in subService.go.
func FormatSubscriptionList(nodes []SubscriptionNode, encrypt bool) string {
	var urls []string
	for _, n := range nodes {
		if n.URL != "" {
			urls = append(urls, strings.TrimSpace(n.URL))
		}
	}

	content := strings.Join(urls, "\n")
	if !encrypt {
		return content
	}

	// Base64 encoding for subscription clients compatibility
	return base64.StdEncoding.EncodeToString([]byte(content))
}
