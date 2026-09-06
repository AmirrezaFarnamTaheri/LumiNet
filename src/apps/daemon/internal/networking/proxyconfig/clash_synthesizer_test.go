package proxyconfig

import (
	"strings"
	"testing"
)

func TestClashSynthesizer(t *testing.T) {
	synth := NewClashSynthesizer(7890)
	synth.AddProxy(ClashProxy{
		Name:    "US-Fast",
		Type:    "vless",
		Server:  "us.node.net",
		Port:    443,
		UUID:    "uuid-123",
		Latency: 80,
	})
	synth.AddGroup(ClashProxyGroup{
		Name:     "Auto-Select",
		Type:     "url-test",
		Proxies:  []string{"US-Fast"},
		URL:      "http://www.gstatic.com/generate_204",
		Interval: 300,
	})

	yaml := synth.SynthesizeYAML()
	if !strings.Contains(yaml, "mixed-port: 7890") {
		t.Errorf("missing mixed-port")
	}
	if !strings.Contains(yaml, "name: \"US-Fast\"") {
		t.Errorf("missing proxy entry")
	}
}
