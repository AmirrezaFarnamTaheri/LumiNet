package proxyconfig

import (
	"sort"
	"strings"
	"sync"
)

type NodeEndpointKey struct {
	Host     string
	Port     uint16
	Protocol string
}

type ScrapedNode struct {
	Host     string
	Port     uint16
	Protocol string
	Source   string
	PingMs   uint32
	IsAlive  bool
}

type NodeIngestDeduplicator struct {
	mu            sync.RWMutex
	seenEndpoints map[NodeEndpointKey]struct{}
	uniqueNodes   []ScrapedNode
	sourceStats   map[string]int
}

func NewNodeIngestDeduplicator() *NodeIngestDeduplicator {
	return &NodeIngestDeduplicator{
		seenEndpoints: make(map[NodeEndpointKey]struct{}),
		uniqueNodes:   make([]ScrapedNode, 0),
		sourceStats:   make(map[string]int),
	}
}

func (d *NodeIngestDeduplicator) IngestNode(node ScrapedNode) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := NodeEndpointKey{
		Host:     strings.ToLower(strings.TrimSpace(node.Host)),
		Port:     node.Port,
		Protocol: strings.ToLower(strings.TrimSpace(node.Protocol)),
	}

	if _, exists := d.seenEndpoints[key]; exists {
		return false
	}

	d.seenEndpoints[key] = struct{}{}
	d.sourceStats[node.Source]++
	d.uniqueNodes = append(d.uniqueNodes, node)
	return true
}

func (d *NodeIngestDeduplicator) GetRankedNodes() []ScrapedNode {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var alive []ScrapedNode
	for _, n := range d.uniqueNodes {
		if n.IsAlive {
			alive = append(alive, n)
		}
	}

	sort.Slice(alive, func(i, j int) bool {
		return alive[i].PingMs < alive[j].PingMs
	})

	return alive
}

func (d *NodeIngestDeduplicator) TotalUnique() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.uniqueNodes)
}

func (d *NodeIngestDeduplicator) CountForSource(source string) int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.sourceStats[source]
}
