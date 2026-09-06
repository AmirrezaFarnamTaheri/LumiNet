package routing

import (
	"net"
	"testing"
)

func TestCompositeRuleCompiler(t *testing.T) {
	compiler := NewCompositeRuleCompiler()
	if !compiler.ParseLine("DOMAIN-SUFFIX,apple.com,DIRECT") {
		t.Fatal("failed to parse domain suffix")
	}
	if !compiler.ParseLine("DOMAIN-KEYWORD,google,PROXY") {
		t.Fatal("failed to parse domain keyword")
	}
	if !compiler.ParseLine("IP-CIDR,192.168.0.0/16,DIRECT") {
		t.Fatal("failed to parse ip cidr")
	}
	if !compiler.ParseLine("IP-CIDR,10.0.0.0/8,REJECT") {
		t.Fatal("failed to parse ip cidr reject")
	}

	act, ok := compiler.EvaluateDomain("music.apple.com")
	if !ok || act != RuleActionDirect {
		t.Fatalf("expected direct, got %s, %v", act, ok)
	}

	act, ok = compiler.EvaluateDomain("www.google.com.hk")
	if !ok || act != RuleActionProxy {
		t.Fatalf("expected proxy, got %s, %v", act, ok)
	}

	_, ok = compiler.EvaluateDomain("unrelated.org")
	if ok {
		t.Fatal("expected no match for unrelated.org")
	}

	act, ok = compiler.EvaluateIP(net.ParseIP("192.168.1.100"))
	if !ok || act != RuleActionDirect {
		t.Fatalf("expected direct, got %s, %v", act, ok)
	}

	act, ok = compiler.EvaluateIP(net.ParseIP("10.5.0.1"))
	if !ok || act != RuleActionReject {
		t.Fatalf("expected reject, got %s, %v", act, ok)
	}

	_, ok = compiler.EvaluateIP(net.ParseIP("8.8.8.8"))
	if ok {
		t.Fatal("expected no match for 8.8.8.8")
	}
}
