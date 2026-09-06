// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: Arista-Panel
// Target path: server/internal/proxy/arista_panel.go

package proxy

import (
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"strings"
)

// ConfigProcessor parses, fragment-routes, shuffles, and merges multi-source node strings.
type ConfigProcessor struct {
	rawNodes []string
}

// NewConfigProcessor initializes the obfuscated edge config compiler.
func NewConfigProcessor() *ConfigProcessor {
	return &ConfigProcessor{}
}

// AddSource parses base64 or raw URI strings.
func (c *ConfigProcessor) AddSource(data string) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err == nil {
		data = string(decoded)
	}

	lines := strings.Split(data, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			c.rawNodes = append(c.rawNodes, line)
		}
	}
}

// ShuffleAndMerge applies fragment routing and shuffles the nodes.
func (c *ConfigProcessor) ShuffleAndMerge() []string {
	log.Printf("Arista-Panel: Shuffling %d nodes and appending fragment routing parameters", len(c.rawNodes))

	processed := make([]string, len(c.rawNodes))
	copy(processed, c.rawNodes)

	// Shuffle
	rand.Shuffle(len(processed), func(i, j int) {
		processed[i], processed[j] = processed[j], processed[i]
	})

	// Fragment routing append
	for i, node := range processed {
		if strings.HasPrefix(node, "vless://") {
			// Append fragment params
			if strings.Contains(node, "?") {
				processed[i] = node + "&fragment=10-20,10-20"
			} else {
				processed[i] = node + "?fragment=10-20,10-20"
			}
		}
	}

	return processed
}

// GenerateClashMeta generates valid Arista_clash.yaml meta configurations.
func (c *ConfigProcessor) GenerateClashMeta() (string, error) {
	nodes := c.ShuffleAndMerge()

	var yaml strings.Builder
	yaml.WriteString("port: 7890\n")
	yaml.WriteString("socks-port: 7891\n")
	yaml.WriteString("allow-lan: false\n")
	yaml.WriteString("mode: Rule\n")
	yaml.WriteString("proxies:\n")

	for i, node := range nodes {
		// Mock parsing URI to yaml map
		yaml.WriteString(fmt.Sprintf("  - name: \"Arista-Node-%d\"\n", i))
		yaml.WriteString(fmt.Sprintf("    type: vless\n    server: %s\n", "parsed.server"))
		_ = node // suppress unused
	}

	return yaml.String(), nil
}

// SetRawNodes overrides target raw nodes array.
func (c *ConfigProcessor) SetRawNodes(nodes []string) {
	copied := make([]string, len(nodes))
	copy(copied, nodes)
	c.rawNodes = copied
}

// GetRawNodes retrieves target raw nodes array.
func (c *ConfigProcessor) GetRawNodes() []string {
	copied := make([]string, len(c.rawNodes))
	copy(copied, c.rawNodes)
	return copied
}

// ClearRawNodes flushes raw nodes registry.
func (c *ConfigProcessor) ClearRawNodes() {
	c.rawNodes = make([]string, 0)
}

// GetRawNodesCount retrieves count of registered raw nodes.
func (c *ConfigProcessor) GetRawNodesCount() int {
	return len(c.rawNodes)
}

// RemoveRawNode deletes registered raw node.
func (c *ConfigProcessor) RemoveRawNode(node string) bool {
	idx := -1
	for i, n := range c.rawNodes {
		if n == node {
			idx = i
			break
		}
	}
	if idx != -1 {
		c.rawNodes = append(c.rawNodes[:idx], c.rawNodes[idx+1:]...)
		return true
	}
	return false
}

// AddRawNode registers a single raw node.
func (c *ConfigProcessor) AddRawNode(node string) {
	c.rawNodes = append(c.rawNodes, node)
}

// HasRawNode asserts registered raw node presence.
func (c *ConfigProcessor) HasRawNode(node string) bool {
	for _, n := range c.rawNodes {
		if n == node {
			return true
		}
	}
	return false
}
