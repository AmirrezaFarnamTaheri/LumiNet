package sub

import (
	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
	"testing"
)

func TestShapeProxyConfig(t *testing.T) {
	template := &proxyconfig.ProxyConfig{Protocol: proxyconfig.ProtocolVLESS, Address: "my-cdn.com", Port: 443, UUID: "9de78a2e-4b7b-4171-ba47-19ad0d7f9503", TLS: true, Transport: "ws", Name: "TemplateProxy"}
	reshaped, err := ShapeProxyConfig(template, []string{"104.16.0.1", "104.16.0.2"}, "{name} - {ip}")
	if err != nil {
		t.Fatal(err)
	}
	if len(reshaped) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(reshaped))
	}
	if reshaped[0].Address != "104.16.0.1" || reshaped[0].SNI != "my-cdn.com" || reshaped[0].Host != "my-cdn.com" || reshaped[0].Name != "TemplateProxy - 104.16.0.1" {
		t.Fatalf("unexpected shape: %+v", reshaped[0])
	}
}
