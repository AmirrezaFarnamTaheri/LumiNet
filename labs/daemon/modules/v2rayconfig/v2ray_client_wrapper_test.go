package v2rayconfig

import (
	"strings"
	"testing"
)

func TestErrorHandlerMock(t *testing.T) {
	msg, code := ErrorHandlerMock(404)
	if code != 404 || !strings.Contains(msg, "404") {
		t.Errorf("404 handler failed: msg=%q, code=%d", msg, code)
	}

	msg, code = ErrorHandlerMock(500)
	if code != 500 || !strings.Contains(msg, "500") {
		t.Errorf("500 handler failed: msg=%q, code=%d", msg, code)
	}
}

func TestShellContextMock(t *testing.T) {
	cfg := &V2rayConfigModel{Key: "dns", Value: "1.1.1.1"}
	ctx := ShellContextMock("my-db-handle", cfg)
	if ctx["db"] != "my-db-handle" || ctx["v2rayConfig"] != cfg {
		t.Error("ShellContextMock failed to return expected variables mappings")
	}
}

func TestBuildVMessClientConfig(t *testing.T) {
	res := BuildVMessClientConfig("my-host.com", 443, "uuid-123", "/ws")
	if !strings.Contains(res, "my-host.com") || !strings.Contains(res, "443") || !strings.Contains(res, "uuid-123") {
		t.Errorf("BuildVMessClientConfig failed: %s", res)
	}
}
