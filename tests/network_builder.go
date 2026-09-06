// Package integration provides cross-module integration harnesses for
// LumiNet's network-layer subsystems.
//
// Target path: tests/network_builder.go
//
// Lets tests describe a synthetic network topology (named nodes, links)
// then build an immutable Network snapshot for connectivity assertions.

package integration

import (
	"fmt"
	"sort"
)

// Node is a named host with v4/v6 addresses and the list of services
// advertised on it (port-name tokens like "socks5", "torcontrol").
type Node struct {
	Name     string
	IPv4     string
	IPv6     string
	Services []string
}

// NetworkBuilder collects node definitions and links, then freezes them
// into a Network via Build(). Chainable: AddNode / Link return the
// receiver.
type NetworkBuilder struct {
	nodes map[string]*Node
	links [][2]string
}

// NewNetworkBuilder returns an empty builder.
func NewNetworkBuilder() *NetworkBuilder {
	return &NetworkBuilder{nodes: make(map[string]*Node)}
}

// AddNode registers a node. Chainable. Errors surface as panic-equiv at
// Build() so the chain stays clean — duplicate names return the existing
// node silently rather than abort mid-chain.
func (b *NetworkBuilder) AddNode(name, ipv4, ipv6 string, services ...string) *NetworkBuilder {
	if _, ok := b.nodes[name]; !ok {
		b.nodes[name] = &Node{
			Name:     name,
			IPv4:     ipv4,
			IPv6:     ipv6,
			Services: append([]string(nil), services...),
		}
	}
	return b
}

// Link records an undirected edge between two named nodes. Chainable.
// Unknown endpoints are deferred to Build() for validation.
func (b *NetworkBuilder) Link(a, c string) *NetworkBuilder {
	b.links = append(b.links, [2]string{a, c})
	return b
}

// Build validates the deferred Link errors and returns the frozen Network.
func (b *NetworkBuilder) Build() (*Network, error) {
	for i, l := range b.links {
		if _, ok := b.nodes[l[0]]; !ok {
			return nil, fmt.Errorf("network_builder: link %d unknown node %q", i, l[0])
		}
		if _, ok := b.nodes[l[1]]; !ok {
			return nil, fmt.Errorf("network_builder: link %d unknown node %q", i, l[1])
		}
	}
	nodes := make(map[string]*Node, len(b.nodes))
	for k, v := range b.nodes {
		nodes[k] = v
	}
	links := append([][2]string(nil), b.links...)
	return &Network{nodes: nodes, links: links}, nil
}

// Network is an immutable snapshot of a built topology.
type Network struct {
	nodes map[string]*Node
	links [][2]string
}

// Nodes returns a snapshot of all nodes, sorted by name for stable output.
func (n *Network) Nodes() []Node {
	out := make([]Node, 0, len(n.nodes))
	for _, v := range n.nodes {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Links returns a snapshot of all undirected edges.
func (n *Network) Links() [][2]string {
	return append([][2]string(nil), n.links...)
}

// Adjacency returns the sorted neighbor names of `name`. Returns an error
// when the name is unknown.
func (n *Network) Adjacency(name string) ([]string, error) {
	if _, ok := n.nodes[name]; !ok {
		return nil, fmt.Errorf("network_builder: unknown node %q", name)
	}
	seen := make(map[string]struct{})
	for _, l := range n.links {
		if l[0] == name {
			seen[l[1]] = struct{}{}
		} else if l[1] == name {
			seen[l[0]] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}
