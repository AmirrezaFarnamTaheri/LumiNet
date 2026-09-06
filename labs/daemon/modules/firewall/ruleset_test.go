package firewall

import (
	"net"
	"testing"
)

func TestRulesetEvaluate(t *testing.T) {
	rs := NewRuleset()

	_, cidr, _ := net.ParseCIDR("192.168.1.0/24")

	// Rule 1: Block TCP traffic to 192.168.1.0/24:80
	rs.AddRule(Rule{
		ID:       "rule-1",
		Action:   ActionBlock,
		Protocol: "tcp",
		DstCIDR:  cidr,
		DstPort:  80,
	})

	blockedPkt := &Packet{
		Protocol: "tcp",
		DstIP:    net.ParseIP("192.168.1.50"),
		DstPort:  80,
	}

	if act := rs.Evaluate(blockedPkt); act != ActionBlock {
		t.Errorf("expected ActionBlock, got %v", act)
	}

	allowedPkt := &Packet{
		Protocol: "tcp",
		DstIP:    net.ParseIP("10.0.0.1"),
		DstPort:  80,
	}

	if act := rs.Evaluate(allowedPkt); act != ActionAllow {
		t.Errorf("expected ActionAllow, got %v", act)
	}
}
