package proxyconfig

import (
	"strings"
	"testing"
)

func TestPrivoxyActionGenerator(t *testing.T) {
	gen := NewPrivoxyActionGenerator("127.0.0.1:10808")
	gen.AddForwardDomain("google.com")
	gen.AddForwardDomain("facebook.com")
	gen.AddDirectBypass("local.lan")

	action := gen.GenerateActionFile()
	if !strings.Contains(action, "{-forward-override}\n.local.lan") {
		t.Fatalf("expected bypass for local.lan, got: %s", action)
	}
	if !strings.Contains(action, "{+forward-override{forward-socks5 127.0.0.1:10808 .}}\n.facebook.com\n.google.com") {
		t.Fatalf("expected socks5 forwards, got: %s", action)
	}
}
