package transport

import (
	"strings"
	"testing"
)

func TestCensorshipTriggerGenerator(t *testing.T) {
	gen := NewCensorshipTriggerGenerator()
	if gen.TotalProbes() < 4 {
		t.Fatalf("expected at least 4 default probes, got %d", gen.TotalProbes())
	}

	sniProbes := gen.GetProbesByCategory(ProbeCategorySniPattern)
	if len(sniProbes) == 0 {
		t.Fatal("expected sni probes")
	}
	if sniProbes[0].PayloadString != "zh.wikipedia.org" {
		t.Fatalf("expected zh.wikipedia.org, got %s", sniProbes[0].PayloadString)
	}

	probe := gen.GenerateHTTPProbe("zh.wikipedia.org", "/wiki/Test")
	probeStr := string(probe)
	if !strings.Contains(probeStr, "Host: zh.wikipedia.org") {
		t.Fatalf("expected Host header, got %s", probeStr)
	}
	if !strings.Contains(probeStr, "GET /wiki/Test HTTP/1.1") {
		t.Fatalf("expected GET line, got %s", probeStr)
	}
}
