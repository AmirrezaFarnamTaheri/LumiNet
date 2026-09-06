package sub

import (
	"strings"
	"testing"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

func transformNode(name, addr string, port int) *proxyconfig.ProxyConfig {
	return &proxyconfig.ProxyConfig{Name: name, Protocol: proxyconfig.ProtocolSOCKS5, Address: addr, Port: port}
}

func TestTransformConfigsFilterRenameSortAndDeduplicate(t *testing.T) {
	a := transformNode("US alpha", "198.51.100.1", 1080)
	dup := transformNode("US duplicate", "198.51.100.1", 1080)
	b := transformNode("EU beta", "203.0.113.2", 1080)
	got, report, err := TransformConfigs([]*proxyconfig.ProxyConfig{b, dup, a}, TransformSpec{
		Include: []string{`^US `}, Deduplicate: true, SortBy: "name",
		Rename: []RenameRule{{Pattern: `^US `, Replacement: ""}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "duplicate" {
		t.Fatalf("unexpected transformed nodes: len=%d name=%q node=%+v", len(got), got[0].Name, got[0])
	}
	if report.Filtered != 1 || report.Deduplicated != 1 || report.Renamed != 1 || report.OutputNodes != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if a.Name != "US alpha" || dup.Name != "US duplicate" {
		t.Fatal("transform mutated source nodes")
	}
}

func TestTransformConfigsPreservesAndRebindsDetourGraph(t *testing.T) {
	a := transformNode("entry", "198.51.100.1", 1080)
	b := transformNode("exit", "203.0.113.2", 1080)
	a.Detour = b
	a.DialerProxy = b.Name
	got, _, err := TransformConfigs([]*proxyconfig.ProxyConfig{a, b}, TransformSpec{Rename: []RenameRule{{Pattern: `^exit$`, Replacement: "egress"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Detour != got[1] || got[0].DialerProxy != "egress" || got[1].Name != "egress" {
		t.Fatalf("detour graph not rebound: entry=%+v exit=%+v", got[0], got[1])
	}
	if got[0].Detour == b {
		t.Fatal("transformed graph points back into source graph")
	}
}

func TestTransformConfigsRejectsOrphaningFilterOrLimit(t *testing.T) {
	a := transformNode("entry", "198.51.100.1", 1080)
	b := transformNode("exit", "203.0.113.2", 1080)
	a.Detour = b
	if _, _, err := TransformConfigs([]*proxyconfig.ProxyConfig{a, b}, TransformSpec{Exclude: []string{`^exit$`}}); err == nil || !strings.Contains(err.Error(), "orphan") {
		t.Fatalf("orphaning filter accepted: %v", err)
	}
	if _, _, err := TransformConfigs([]*proxyconfig.ProxyConfig{a, b}, TransformSpec{Limit: 1}); err == nil || !strings.Contains(err.Error(), "orphan") {
		t.Fatalf("orphaning limit accepted: %v", err)
	}
}

func TestTransformConfigsBoundsAndRegexValidation(t *testing.T) {
	n := transformNode("node", "198.51.100.1", 1080)
	if _, _, err := TransformConfigs([]*proxyconfig.ProxyConfig{n}, TransformSpec{Include: []string{"["}}); err == nil {
		t.Fatal("invalid regex accepted")
	}
	if _, _, err := TransformConfigs([]*proxyconfig.ProxyConfig{n}, TransformSpec{Limit: maxConversionNodes + 1}); err == nil {
		t.Fatal("oversized limit accepted")
	}
}
