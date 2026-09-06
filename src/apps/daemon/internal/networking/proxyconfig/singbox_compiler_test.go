package proxyconfig

import (
	"strings"
	"testing"
)

func TestSingboxCompiler(t *testing.T) {
	c := NewSingboxCompiler()
	c.AddRule("domain_suffix", "openai.com", "openai-out")
	c.AddRule("geosite", "cn", "direct")

	out, ok := c.MatchDomain("api.openai.com")
	if !ok || out != "openai-out" {
		t.Errorf("expected openai-out for api.openai.com")
	}

	out, ok = c.MatchDomain("www.baidu.cn")
	if !ok || out != "direct" {
		t.Errorf("expected direct for www.baidu.cn")
	}

	jsonStr := c.ExportJSON()
	if !strings.Contains(jsonStr, "\"outbound\": \"openai-out\"") {
		t.Errorf("missing outbound tag in exported json")
	}
}
