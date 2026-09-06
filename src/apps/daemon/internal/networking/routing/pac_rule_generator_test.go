package routing

import (
	"strings"
	"testing"
)

func TestPacRuleGenerator(t *testing.T) {
	gen := NewPacRuleGenerator(PacRuleActionDirect, "")
	gen.AddRule("||google.com", PacRuleActionProxy, "127.0.0.1:1080")
	gen.AddRule("|internal.corp", PacRuleActionDirect, "")

	act, ep := gen.EvaluateHost("mail.google.com")
	if act != PacRuleActionProxy || ep != "127.0.0.1:1080" {
		t.Fatalf("expected proxy for mail.google.com, got %s, %s", act, ep)
	}

	act, _ = gen.EvaluateHost("internal.corp")
	if act != PacRuleActionDirect {
		t.Fatalf("expected direct for internal.corp, got %s", act)
	}

	act, _ = gen.EvaluateHost("unknown.org")
	if act != PacRuleActionDirect {
		t.Fatalf("expected direct for unknown.org, got %s", act)
	}

	script := gen.GeneratePacScript()
	if !strings.Contains(script, "FindProxyForURL") || !strings.Contains(script, "google.com") {
		t.Fatalf("PAC script missing required elements")
	}

	dnsmasq := gen.GenerateDnsmasqConfig("1.1.1.1")
	if !strings.Contains(dnsmasq, "server=/google.com/1.1.1.1") {
		t.Fatalf("Dnsmasq missing rule")
	}
}
