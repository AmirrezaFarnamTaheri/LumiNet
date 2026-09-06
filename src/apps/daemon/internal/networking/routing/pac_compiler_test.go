package routing

import (
	"net"
	"strings"
	"testing"
)

func TestPacCompiler(t *testing.T) {
	compiler := NewPacScriptCompiler("127.0.0.1:1080")
	compiler.AddDirectDomain("baidu.com")
	compiler.AddProxyDomain("google.com")
	_ = compiler.AddCnCidr("223.5.5.0/24")

	if compiler.EvaluateDomain("google.com") != "PROXY 127.0.0.1:1080" {
		t.Errorf("expected google.com to be PROXY")
	}
	if compiler.EvaluateDomain("sub.google.com") != "PROXY 127.0.0.1:1080" {
		t.Errorf("expected sub.google.com to be PROXY")
	}
	if compiler.EvaluateDomain("baidu.com") != "DIRECT" {
		t.Errorf("expected baidu.com to be DIRECT")
	}

	ip := net.ParseIP("223.5.5.5")
	if compiler.EvaluateIP(ip) != "DIRECT" {
		t.Errorf("expected 223.5.5.5 to be DIRECT")
	}

	pac := compiler.CompilePacScript()
	if !strings.Contains(pac, "PROXY 127.0.0.1:1080") {
		t.Errorf("missing proxy string in pac")
	}
}
