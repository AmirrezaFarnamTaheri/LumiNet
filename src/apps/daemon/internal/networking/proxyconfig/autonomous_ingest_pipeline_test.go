package proxyconfig

import (
	"testing"

	"github.com/maybeknott/luminet/internal/networking/routing"
)

func TestAutonomousIngestPipeline(t *testing.T) {
	pipeline := NewAutonomousIngestPipeline(routing.PolicyVerdictDirect)

	pipeline.GeoIP.AddCidr([4]byte{223, 5, 5, 0}, 24, "CN")
	pipeline.RuleCompiler.ParseLine("DOMAIN-SUFFIX,google.com,PROXY")
	pipeline.RuleCompiler.ParseLine("DOMAIN-SUFFIX,ads.evil.com,REJECT")

	// Direct because CN GeoIP
	cnIP := [4]byte{223, 5, 5, 5}
	v1 := pipeline.EvaluateEgress("some-cn-site.cn", &cnIP)
	if v1 != routing.PolicyVerdictDirect {
		t.Fatalf("expected Direct, got %s", v1)
	}

	// Proxy because domain rule
	v2 := pipeline.EvaluateEgress("mail.google.com", nil)
	if v2 != routing.PolicyVerdictProxy {
		t.Fatalf("expected Proxy, got %s", v2)
	}

	// Reject because domain rule
	v3 := pipeline.EvaluateEgress("tracker.ads.evil.com", nil)
	if v3 != routing.PolicyVerdictReject {
		t.Fatalf("expected Reject, got %s", v3)
	}
}
