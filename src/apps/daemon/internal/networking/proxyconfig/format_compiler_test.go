package proxyconfig

import (
	"strings"
	"testing"
)

func TestMultiFormatCompiler(t *testing.T) {
	compiler := &MultiFormatCompiler{}
	def := &UnifiedOutboundDefinition{
		Tag:           "test-node",
		Protocol:      "vless",
		Server:        "node.luminet.net",
		ServerPort:    443,
		UUID:          "12345678-1234-1234-1234-123456789abc",
		TLSSNI:        "node.luminet.net",
		TransportType: "ws",
		WsPath:        "/tunnel",
	}

	sb := compiler.CompileSingBox(def)
	if !strings.Contains(sb, `"type":"vless"`) || !strings.Contains(sb, `"server_port":443`) {
		t.Fatalf("singbox compile failed: %s", sb)
	}

	xr := compiler.CompileXray(def)
	if !strings.Contains(xr, `"protocol":"vless"`) || !strings.Contains(xr, `streamSettings`) {
		t.Fatalf("xray compile failed: %s", xr)
	}

	cl := compiler.CompileClash(def)
	if !strings.Contains(cl, `name: "test-node"`) || !strings.Contains(cl, `ws-opts:`) {
		t.Fatalf("clash compile failed: %s", cl)
	}
}
