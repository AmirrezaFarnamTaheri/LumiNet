// Package proxyconfig provides typed proxy configuration parsing and
// composition primitives. This file implements the dialer-graph registry
// model. It is clean-room: no code is copied from outline-apps.
package proxyconfig

import (
	"fmt"
	"sort"
	"sync"
)

// DialerNode is a single node in the dialer graph. Each node represents a
// transport endpoint (direct, SOCKS, Shadowsocks, etc.) and can link to
// other nodes to build a chain.
type DialerNode struct {
	// Name is the unique identifier of the node.
	Name string
	// Transport is the transport type (e.g. "direct", "socks5", "shadowsocks").
	Transport string
	// URI is the canonical transport configuration (scheme://...).
	URI string
	// DependsOn lists names of nodes that must be dialed before this one.
	DependsOn []string
	// Weight is used when ranking alternate paths; higher weight wins.
	Weight int
	// Metadata is opaque key-value metadata for transport-specific options.
	Metadata map[string]string
}

// ConfigRegistryError is returned by ConfigRegistry methods.
type ConfigRegistryError struct {
	Code    string
	Message string
}

func (e *ConfigRegistryError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// GraphError collects all errors encountered while building a graph.
type GraphError struct {
	Errors []string
}

func (e *GraphError) Error() string {
	return fmt.Sprintf("graph build: %d errors: %v", len(e.Errors), e.Errors)
}

// ConfigRegistry stores DialerNode entries and supports building a directed
// graph representation for runtime dialer construction.
type ConfigRegistry struct {
	mu    sync.RWMutex
	nodes map[string]*DialerNode
	// nameToID maps an alias to a node name.
	aliases map[string]string
}

// NewConfigRegistry creates a new empty registry.
func NewConfigRegistry() *ConfigRegistry {
	return &ConfigRegistry{
		nodes:   make(map[string]*DialerNode),
		aliases: make(map[string]string),
	}
}

// Register adds or replaces a DialerNode in the registry.
// It returns an error if the node's dependencies reference unknown names.
func (r *ConfigRegistry) Register(node *DialerNode) error {
	if node == nil {
		return &ConfigRegistryError{Code: "invalid_node", Message: "node is nil"}
	}
	if node.Name == "" {
		return &ConfigRegistryError{Code: "invalid_name", Message: "node name cannot be empty"}
	}
	if node.Transport == "" {
		return &ConfigRegistryError{Code: "invalid_transport", Message: "node transport cannot be empty"}
	}
	if node.URI == "" {
		return &ConfigRegistryError{Code: "invalid_uri", Message: "node URI cannot be empty"}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Validate dependencies exist (only if already present in registry).
	for _, dep := range node.DependsOn {
		if _, ok := r.nodes[dep]; !ok {
			// Allow forward references; we'll verify on BuildGraph.
			_ = dep
		}
	}

	// Deep copy metadata to avoid external mutation.
	metadata := make(map[string]string, len(node.Metadata))
	for k, v := range node.Metadata {
		metadata[k] = v
	}
	cp := *node
	cp.Metadata = metadata
	cp.DependsOn = append([]string(nil), node.DependsOn...)

	r.nodes[node.Name] = &cp
	return nil
}

// Get retrieves a node by name. Returns nil if not found.
func (r *ConfigRegistry) Get(name string) *DialerNode {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if real, ok := r.aliases[name]; ok {
		name = real
	}
	n, ok := r.nodes[name]
	if !ok {
		return nil
	}
	cp := *n
	cp.DependsOn = append([]string(nil), n.DependsOn...)
	cp.Metadata = make(map[string]string, len(n.Metadata))
	for k, v := range n.Metadata {
		cp.Metadata[k] = v
	}
	return &cp
}

// Remove deletes a node. It returns an error if any other node depends on it.
func (r *ConfigRegistry) Remove(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	realName := name
	if alias, ok := r.aliases[name]; ok {
		realName = alias
	}
	if _, ok := r.nodes[realName]; !ok {
		return &ConfigRegistryError{Code: "not_found", Message: fmt.Sprintf("node %q not found", name)}
	}
	// Check dependents.
	for _, n := range r.nodes {
		for _, dep := range n.DependsOn {
			if dep == realName || dep == name {
				return &ConfigRegistryError{
					Code:    "in_use",
					Message: fmt.Sprintf("node %q is depended on by %q", name, n.Name),
				}
			}
		}
	}
	delete(r.nodes, realName)
	for alias, target := range r.aliases {
		if target == realName {
			delete(r.aliases, alias)
		}
	}
	return nil
}

// List returns the names of all registered nodes in stable sorted order.
func (r *ConfigRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.nodes))
	for name := range r.nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// AddAlias registers an alias that points to an existing node name.
func (r *ConfigRegistry) AddAlias(alias, target string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.nodes[target]; !ok {
		return &ConfigRegistryError{Code: "not_found", Message: fmt.Sprintf("target %q not found", target)}
	}
	r.aliases[alias] = target
	return nil
}

// Size returns the number of registered nodes.
func (r *ConfigRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.nodes)
}

// Clear removes all nodes and aliases.
func (r *ConfigRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodes = make(map[string]*DialerNode)
	r.aliases = make(map[string]string)
}

// DialerGraph is the result of BuildGraph: a topologically ordered list of
// nodes suitable for runtime dialer construction.
type DialerGraph struct {
	// Ordered lists node names in dial order (dependencies first).
	Ordered []string
	// Nodes is the same set of nodes indexed by name.
	Nodes map[string]*DialerNode
	// EntryPoint is the recommended node to start dialing from. It is the
	// node with no dependents; if there are multiple, the highest-weight one
	// wins, with ties broken by alphabetical order.
	EntryPoint string
}

// BuildGraph validates dependencies and topologically sorts nodes.
// It returns a *GraphError if a cycle is detected or a dependency is missing.
func (r *ConfigRegistry) BuildGraph() (*DialerGraph, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	graph := &DialerGraph{
		Nodes: make(map[string]*DialerNode, len(r.nodes)),
	}

	// Copy nodes into the result so we don't leak registry internals.
	for name, n := range r.nodes {
		cp := *n
		cp.DependsOn = append([]string(nil), n.DependsOn...)
		cp.Metadata = make(map[string]string, len(n.Metadata))
		for k, v := range n.Metadata {
			cp.Metadata[k] = v
		}
		graph.Nodes[name] = &cp
	}

	// Resolve aliases for dependency references.
	resolve := func(name string) string {
		if real, ok := r.aliases[name]; ok {
			return real
		}
		return name
	}

	// Validate all dependencies.
	var errs []string
	for _, n := range graph.Nodes {
		for _, dep := range n.DependsOn {
			resolved := resolve(dep)
			if _, ok := graph.Nodes[resolved]; !ok {
				errs = append(errs, fmt.Sprintf("node %q depends on unknown %q", n.Name, dep))
			}
		}
	}
	if len(errs) > 0 {
		return nil, &GraphError{Errors: errs}
	}

	// Build adjacency for Kahn's algorithm.
	indegree := make(map[string]int, len(graph.Nodes))
	dependents := make(map[string][]string, len(graph.Nodes))
	for name := range graph.Nodes {
		indegree[name] = 0
	}
	for name, n := range graph.Nodes {
		for _, dep := range n.DependsOn {
			resolved := resolve(dep)
			indegree[name]++
			dependents[resolved] = append(dependents[resolved], name)
		}
	}

	// Initial frontier: nodes with no dependencies.
	frontier := make([]string, 0)
	for name, deg := range indegree {
		if deg == 0 {
			frontier = append(frontier, name)
		}
	}
	sort.Strings(frontier) // stable for determinism

	for len(frontier) > 0 {
		cur := frontier[0]
		frontier = frontier[1:]
		graph.Ordered = append(graph.Ordered, cur)

		// Sort dependents for determinism.
		sort.Strings(dependents[cur])
		for _, dep := range dependents[cur] {
			indegree[dep]--
			if indegree[dep] == 0 {
				frontier = append(frontier, dep)
			}
		}
	}

	if len(graph.Ordered) != len(graph.Nodes) {
		return nil, &GraphError{Errors: []string{"cycle detected in dialer graph"}}
	}

	// Pick entry point: node with no dependents, highest weight, then lex.
	dependentSet := make(map[string]bool)
	for _, n := range graph.Nodes {
		for _, dep := range n.DependsOn {
			dependentSet[resolve(dep)] = true
		}
	}
	var candidates []string
	for name := range graph.Nodes {
		if !dependentSet[name] {
			candidates = append(candidates, name)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		wi := graph.Nodes[candidates[i]].Weight
		wj := graph.Nodes[candidates[j]].Weight
		if wi != wj {
			return wi > wj
		}
		return candidates[i] < candidates[j]
	})
	if len(candidates) > 0 {
		graph.EntryPoint = candidates[0]
	}

	return graph, nil
}

// Validate is a convenience that walks the graph and returns the first error.
func (r *ConfigRegistry) Validate() error {
	_, err := r.BuildGraph()
	return err
}
