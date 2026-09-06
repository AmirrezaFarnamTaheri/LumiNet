package routing

import (
	"testing"
)

func TestAutonomousCoordinator(t *testing.T) {
	coord := NewAutonomousCoordinator("Default-Node")
	coord.AutoProxy().ParseLine("@@||internal.local")
	coord.Pac().AddDirectDomain("taobao.com")

	action, _ := coord.Evaluate("https://internal.local/app")
	if action != ActionDirect {
		t.Errorf("expected internal.local to be DIRECT")
	}

	action, _ = coord.Evaluate("taobao.com")
	if action != ActionDirect {
		t.Errorf("expected taobao.com to be DIRECT")
	}

	action, node := coord.Evaluate("random-blocked.com")
	if action != ActionProxy || node != "Default-Node" {
		t.Errorf("expected random-blocked.com to proxy to Default-Node")
	}
}
