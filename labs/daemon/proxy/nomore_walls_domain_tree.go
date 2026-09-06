// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: NoMoreWalls-master/fetch.py  (Python → Go)
// Target path: server/internal/proxy/nomore_walls_domain_tree.go
//
// Provides:
//   - DomainTree: a trie that stores reversed-segment domain paths, supporting
//     insert, remove, and get (listing all stored domains).
//   - AdblockRuleMerger: parses AdGuard/uBlock ABF files and merges
//     DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR rules into a rule map while
//     honouring whitelist (@@) exceptions.

package proxy

import (
	"net"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// DomainTree
// ─────────────────────────────────────────────────────────────────────────────

// DomainTree is an in-memory trie keyed on reversed domain segments.
// Inserting "example.com" stores segments ["com", "example"] so that
// a subtree rooted at "com" → "example" records the domain.
//
// The here flag at a node means "a rule for exactly the subdomain leading
// to this node is active"; in practice it means the node's corresponding
// domain (e.g. "example.com") should be emitted as a DOMAIN-SUFFIX rule.
//
// Ported faithfully from the DomainTree class in NoMoreWalls fetch.py.
type DomainTree struct {
	children map[string]*DomainTree
	here     bool
}

// NewDomainTree allocates an empty trie root.
func NewDomainTree() *DomainTree {
	return &DomainTree{children: map[string]*DomainTree{}}
}

// Insert adds domain to the trie.  domain is split by "." and reversed before
// descent.  Inserting "example.com" creates path root→"com"→"example" with
// here=true on the "example" node.
func (t *DomainTree) Insert(domain string) {
	segs := splitReversed(domain)
	t.insertSegs(segs)
}

func (t *DomainTree) insertSegs(segs []string) {
	if len(segs) == 0 {
		t.here = true
		return
	}
	seg := segs[0]
	if _, ok := t.children[seg]; !ok {
		t.children[seg] = NewDomainTree()
	}
	t.children[seg].insertSegs(segs[1:])
}

// Remove deletes domain from the trie.  If domain is found, its here flag is
// cleared and its subtree is pruned.  Mirrors the _remove() behaviour in
// fetch.py (which clears here=False and recursively clears children when segs
// are exhausted).
func (t *DomainTree) Remove(domain string) {
	segs := splitReversed(domain)
	t.removeSegs(segs)
}

func (t *DomainTree) removeSegs(segs []string) {
	if len(segs) == 0 {
		t.here = false
		// Clear all children — this domain's entire subtree is whitelisted.
		t.children = map[string]*DomainTree{}
		return
	}
	if child, ok := t.children[segs[0]]; ok {
		child.removeSegs(segs[1:])
	}
}

// Get returns all stored domains in natural "label.tld" order.
// A node with here=true emits its segment path without recursing further
// (because its parent already covers all child subdomains).
func (t *DomainTree) Get() []string {
	var out []string
	for seg, child := range t.children {
		if child.here {
			out = append(out, seg)
		} else {
			for _, sub := range child.Get() {
				out = append(out, sub+"."+seg)
			}
		}
	}
	return out
}

// Len returns the total count of stored domains (including duplicates under
// wildcard ancestors).  Useful for telemetry.
func (t *DomainTree) Len() int {
	return len(t.Get())
}

// splitReversed returns domain.split(".") reversed.
func splitReversed(domain string) []string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(domain)), ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

// ─────────────────────────────────────────────────────────────────────────────
// AdblockRuleMerger
// ─────────────────────────────────────────────────────────────────────────────

// AdblockRuleMerger parses Adblock Plus / AdGuard filter lists and builds a
// Clash/sing-box compatible rule map.  Mirrors merge_adblock() in fetch.py.
//
// Rule map key format: "DOMAIN-SUFFIX,example.com",
//
//	"DOMAIN-KEYWORD,ads",
//	"IP-CIDR,1.2.3.4/32"
//
// Rule map value: the tag (e.g. "ad_block") identifying the rule set.
type AdblockRuleMerger struct {
	blocked    map[string]struct{} // raw ||domain^ entries
	unblocked  map[string]struct{} // raw @@||domain^ / whitelist entries
	keywords   map[string]struct{} // wildcard (*keyword*) domains
	domainRoot *DomainTree
	Rules      map[string]string // output rule map
}

// NewAdblockRuleMerger creates a merger with an empty output rule map.
func NewAdblockRuleMerger() *AdblockRuleMerger {
	return &AdblockRuleMerger{
		blocked:    map[string]struct{}{},
		unblocked:  map[string]struct{}{},
		keywords:   map[string]struct{}{},
		domainRoot: NewDomainTree(),
		Rules:      map[string]string{},
	}
}

// AddBlocklistLine parses one line from a block-list source file.
// Mirrors the block-list portion of merge_adblock() in fetch.py.
// The caller should call Finalise() once all sources are processed.
func (m *AdblockRuleMerger) AddBlocklistLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '!' || line[0] == '#' {
		return
	}
	// Whitelist override: @@||domain^
	if strings.HasPrefix(line, "@@") {
		domain := extractAbpDomain(line[2:])
		if domain != "" {
			m.unblocked[domain] = struct{}{}
		}
		return
	}
	// Block entry: ||domain^ or ||domain$all
	if strings.HasPrefix(line, "||") && !strings.Contains(line, "/") && !strings.Contains(line, "?") {
		last := line[len(line)-1]
		endsCorrectly := last == '^' || strings.HasSuffix(line, "$all")
		if !endsCorrectly {
			return
		}
		domain := stripAbpMarkers(line[2:])
		if strings.Contains(domain, "*") {
			kw := strings.Trim(domain, "*")
			if !strings.Contains(kw, "*") {
				m.keywords[kw] = struct{}{}
			}
			return
		}
		m.blocked[domain] = struct{}{}
	}
}

// AddWhitelistLine parses one line from a whitelist source file.
func (m *AdblockRuleMerger) AddWhitelistLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '!' {
		return
	}
	domain := strings.TrimLeft(strings.Split(line, "^")[0], "|")
	if domain != "" {
		m.unblocked[domain] = struct{}{}
	}
}

// Finalise builds the DomainTree from blocked/unblocked sets, then populates
// Rules.  Call this after feeding all source lines.
// tag is the name emitted as the rule-map value (e.g. "ad_block").
func (m *AdblockRuleMerger) Finalise(tag string) {
	// Populate trie
	for domain := range m.blocked {
		segs := strings.Split(domain, ".")
		// Validate: 4-segment all-digit = IPv4
		if len(segs) == 4 && isIPv4(domain) {
			m.Rules["IP-CIDR,"+domain+"/32"] = tag
		} else {
			m.domainRoot.Insert(domain)
		}
	}
	// Apply whitelist removals
	for domain := range m.unblocked {
		m.domainRoot.Remove(domain)
	}
	// Keyword rules
	for kw := range m.keywords {
		m.Rules["DOMAIN-KEYWORD,"+kw] = tag
	}
	// Domain-suffix rules (skip if subsumed by a keyword)
	for _, domain := range m.domainRoot.Get() {
		subsumed := false
		for kw := range m.keywords {
			if strings.Contains(domain, kw) {
				subsumed = true
				break
			}
		}
		if !subsumed {
			m.Rules["DOMAIN-SUFFIX,"+domain] = tag
		}
	}
}

// RuleCount returns how many rules are in the output map.
func (m *AdblockRuleMerger) RuleCount() int {
	return len(m.Rules)
}

// Helper: extract the domain token from an ABP filter line.
func extractAbpDomain(line string) string {
	// strip leading ||, trailing ^/$...
	line = strings.TrimLeft(line, "|")
	line = strings.Split(line, "^")[0]
	line = strings.Split(line, "$")[0]
	return strings.TrimSpace(line)
}

func stripAbpMarkers(s string) string {
	s = strings.TrimSuffix(s, "$all")
	s = strings.TrimSuffix(s, "^")
	return strings.TrimSpace(s)
}

func isIPv4(s string) bool {
	return net.ParseIP(s) != nil
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeDeduplicator
// ─────────────────────────────────────────────────────────────────────────────

// NodeDeduplicator mirrors the merged dict + hash-dedup logic in fetch.py.
// Proxy node entries (represented as string-keyed maps) are hashed by
// a canonical key and stored once; duplicates update the name set.
type NodeDeduplicator struct {
	mu      strings.Builder // unused, just for clarity
	entries map[string]*DeduplicatedNode
}

// DeduplicatedNode is a merged proxy entry.
type DeduplicatedNode struct {
	Data  map[string]interface{}
	Names map[string]struct{}
}

// NewNodeDeduplicator returns an empty deduplicator.
func NewNodeDeduplicator() *NodeDeduplicator {
	return &NodeDeduplicator{entries: map[string]*DeduplicatedNode{}}
}

// Merge adds or updates an entry.  key is the canonical dedup key
// (e.g. "vmess:1.1.1.1:443:...").  data is the node's property bag.
func (nd *NodeDeduplicator) Merge(key string, data map[string]interface{}) {
	if existing, ok := nd.entries[key]; ok {
		for k, v := range data {
			existing.Data[k] = v
		}
		if name, ok := data["name"].(string); ok {
			existing.Names[name] = struct{}{}
		}
	} else {
		names := map[string]struct{}{}
		if name, ok := data["name"].(string); ok {
			names[name] = struct{}{}
		}
		cp := make(map[string]interface{}, len(data))
		for k, v := range data {
			cp[k] = v
		}
		nd.entries[key] = &DeduplicatedNode{Data: cp, Names: names}
	}
}

// Entries returns all unique nodes (one per canonical key).
func (nd *NodeDeduplicator) Entries() []*DeduplicatedNode {
	out := make([]*DeduplicatedNode, 0, len(nd.entries))
	for _, v := range nd.entries {
		out = append(out, v)
	}
	return out
}

// Count returns the number of unique deduplicated nodes.
func (nd *NodeDeduplicator) Count() int { return len(nd.entries) }
