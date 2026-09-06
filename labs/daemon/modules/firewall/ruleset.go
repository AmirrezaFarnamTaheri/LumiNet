package firewall

import (
	"net"
	"strings"
	"sync"
)

// Action defines the firewall decision for a matching packet flow.
type Action int

const (
	ActionAllow Action = iota
	ActionBlock
	ActionRedirect
)

// Packet represents packet attributes evaluated by firewall rules.
type Packet struct {
	Protocol string
	SrcIP    net.IP
	DstIP    net.IP
	DstPort  uint16
	AppPath  string
}

// Rule defines a firewall matching rule.
type Rule struct {
	ID       string
	Action   Action
	Protocol string
	DstCIDR  *net.IPNet
	DstPort  uint16
	AppPath  string
}

// Ruleset maintains active firewall rules and evaluates inbound/outbound packets.
type Ruleset struct {
	mu    sync.RWMutex
	rules []Rule
}

// NewRuleset creates an empty Ruleset.
func NewRuleset() *Ruleset {
	return &Ruleset{rules: make([]Rule, 0)}
}

// AddRule appends a rule to the active ruleset.
func (r *Ruleset) AddRule(rule Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = append(r.rules, rule)
}

// Evaluate checks packet parameters against rules in order, returning the first matching Action.
func (r *Ruleset) Evaluate(pkt *Packet) Action {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, rule := range r.rules {
		if rule.Protocol != "" && rule.Protocol != "*" && !strings.EqualFold(rule.Protocol, pkt.Protocol) {
			continue
		}
		if rule.DstPort != 0 && rule.DstPort != pkt.DstPort {
			continue
		}
		if rule.DstCIDR != nil && pkt.DstIP != nil && !rule.DstCIDR.Contains(pkt.DstIP) {
			continue
		}
		if rule.AppPath != "" && !strings.Contains(strings.ToLower(pkt.AppPath), strings.ToLower(rule.AppPath)) {
			continue
		}
		return rule.Action
	}
	return ActionAllow // Default policy
}
