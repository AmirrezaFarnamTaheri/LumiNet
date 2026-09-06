package proxyconfig

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type AggregatedNode struct {
	ID           string   `json:"id"`
	Protocol     string   `json:"protocol"`
	Host         string   `json:"host"`
	Port         uint16   `json:"port"`
	Score        float64  `json:"score"`
	LatencyMs    uint32   `json:"latency_ms"`
	SuccessCount uint32   `json:"success_count"`
	FailureCount uint32   `json:"failure_count"`
	Tags         []string `json:"tags"`
	LastSeen     int64    `json:"last_seen"`
}

type NodePoolAggregator struct {
	nodes map[string]*AggregatedNode
}

func NewNodePoolAggregator() *NodePoolAggregator {
	return &NodePoolAggregator{
		nodes: make(map[string]*AggregatedNode),
	}
}

func (n *NodePoolAggregator) IngestRawEntries(entries []string, timestamp int64) int {
	count := 0
	for _, raw := range entries {
		node := n.parseRawLine(raw, timestamp)
		if node != nil {
			key := fmt.Sprintf("%s:%s:%d", node.Protocol, node.Host, node.Port)
			if existing, ok := n.nodes[key]; ok {
				existing.LastSeen = timestamp
				for _, tag := range node.Tags {
					found := false
					for _, t := range existing.Tags {
						if t == tag {
							found = true
							break
						}
					}
					if !found {
						existing.Tags = append(existing.Tags, tag)
					}
				}
			} else {
				n.nodes[key] = node
			}
			count++
		}
	}
	return count
}

func (n *NodePoolAggregator) UpdateHealth(id string, latencyMs uint32, success bool) bool {
	node, ok := n.nodes[id]
	if !ok {
		return false
	}

	if success {
		node.SuccessCount++
		node.LatencyMs = (node.LatencyMs*3 + latencyMs) / 4
		lat := float64(node.LatencyMs)
		if lat < 10 {
			lat = 10
		}
		latScore := 1000.0 / lat
		if latScore > 100.0 {
			latScore = 100.0
		}
		rel := float64(node.SuccessCount) / float64(node.SuccessCount+node.FailureCount)
		node.Score = (latScore * 0.4) + (rel * 60.0)
	} else {
		node.FailureCount++
		rel := float64(node.SuccessCount) / float64(node.SuccessCount+node.FailureCount)
		if node.Score > rel*60.0 {
			node.Score = rel * 60.0
		}
	}
	return true
}

func (n *NodePoolAggregator) RankNodes(minScore float64) []*AggregatedNode {
	var list []*AggregatedNode
	for _, node := range n.nodes {
		if node.Score >= minScore {
			list = append(list, node)
		}
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Score > list[j].Score
	})
	return list
}

func (n *NodePoolAggregator) ExportPoolJSON() string {
	var list []*AggregatedNode
	for _, v := range n.nodes {
		list = append(list, v)
	}
	data, _ := json.MarshalIndent(list, "", "  ")
	return string(data)
}

func (n *NodePoolAggregator) parseRawLine(raw string, timestamp int64) *AggregatedNode {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil
	}

	idx := strings.Index(trimmed, "://")
	if idx == -1 {
		return nil
	}

	protocol := strings.ToLower(trimmed[:idx])
	rem := trimmed[idx+3:]

	parts := strings.Split(rem, "@")
	hostPort := parts[0]
	if len(parts) > 1 {
		hostPort = parts[1]
	}

	hostSplit := strings.Split(hostPort, ":")
	if len(hostSplit) < 2 {
		return nil
	}

	host := hostSplit[0]
	portStr := strings.FieldsFunc(hostSplit[1], func(r rune) bool {
		return r == '/' || r == '?' || r == '#'
	})
	if len(portStr) == 0 {
		return nil
	}

	p, err := strconv.ParseUint(portStr[0], 10, 16)
	if err != nil {
		p = 443
	}

	id := fmt.Sprintf("%s:%s:%d", protocol, host, p)
	return &AggregatedNode{
		ID:           id,
		Protocol:     protocol,
		Host:         host,
		Port:         uint16(p),
		Score:        50.0,
		LatencyMs:    200,
		SuccessCount: 1,
		FailureCount: 0,
		Tags:         []string{"public_pool"},
		LastSeen:     timestamp,
	}
}
