package routing

import (
	"bufio"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

// SplitRoutingAction defines VPN routing action
type SplitRoutingAction int

const (
	ActionRouteThroughVPN SplitRoutingAction = iota
	ActionBypassVPN
	ActionDropTraffic
)

// SplitTunnelRule defines CIDR route matching
type SplitTunnelRule struct {
	ID        string
	IPNet     *net.IPNet
	PrefixLen int
	Action    SplitRoutingAction
	Priority  uint32
}

// SplitTunnelRuleSync synchronizes dynamic split-tunnel rules
type SplitTunnelRuleSync struct {
	mu            sync.RWMutex
	Rules         []*SplitTunnelRule
	DefaultAction SplitRoutingAction
	SyncVersion   uint64
}

// NewSplitTunnelRuleSync creates a rule synchronizer
func NewSplitTunnelRuleSync(defaultAction SplitRoutingAction) *SplitTunnelRuleSync {
	return &SplitTunnelRuleSync{
		DefaultAction: defaultAction,
	}
}

// AddRule adds and sorts a CIDR routing rule
func (s *SplitTunnelRuleSync) AddRule(id, cidr string, action SplitRoutingAction, priority uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		ip := net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid CIDR or IP format: %s", cidr)
		}
		mask := net.CIDRMask(32, 32)
		ipNet = &net.IPNet{IP: ip.To4(), Mask: mask}
	}

	ones, _ := ipNet.Mask.Size()
	rule := &SplitTunnelRule{
		ID:        id,
		IPNet:     ipNet,
		PrefixLen: ones,
		Action:    action,
		Priority:  priority,
	}

	s.Rules = append(s.Rules, rule)
	s.sortRules()
	s.SyncVersion++
	return nil
}

func (s *SplitTunnelRuleSync) sortRules() {
	sort.Slice(s.Rules, func(i, j int) bool {
		if s.Rules[i].Priority != s.Rules[j].Priority {
			return s.Rules[i].Priority > s.Rules[j].Priority
		}
		return s.Rules[i].PrefixLen > s.Rules[j].PrefixLen
	})
}

// MatchIP resolves action using longest prefix match
func (s *SplitTunnelRuleSync) MatchIP(ip net.IP) SplitRoutingAction {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, rule := range s.Rules {
		if rule.IPNet.Contains(ip) {
			return rule.Action
		}
	}
	return s.DefaultAction
}

// SyncFromFeed imports raw text feed of CIDRs
func (s *SplitTunnelRuleSync) SyncFromFeed(feedContent string, action SplitRoutingAction) int {
	scanner := bufio.NewScanner(strings.NewReader(feedContent))
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id := fmt.Sprintf("feed-%d", count+1)
		if err := s.AddRule(id, line, action, 100); err == nil {
			count++
		}
	}
	return count
}
