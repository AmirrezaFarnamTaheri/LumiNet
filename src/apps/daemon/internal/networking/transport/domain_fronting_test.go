package transport

import (
	"strings"
	"testing"
)

func TestBuildFrontedRequest(t *testing.T) {
	cfg := DomainFrontingConfig{
		FrontDomain: "ajax.microsoft.com",
		OriginHost:  "target-node.internal",
		TargetURI:   "/tunnel/connect",
		CustomHeaders: map[string]string{
			"X-Tunnel-Key": "auth123",
		},
	}

	req, err := BuildFrontedRequest(cfg, "POST")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if req.SNIHost != "ajax.microsoft.com" {
		t.Errorf("expected SNIHost ajax.microsoft.com, got %s", req.SNIHost)
	}
	if req.HostHeader != "target-node.internal" {
		t.Errorf("expected Host target-node.internal, got %s", req.HostHeader)
	}
	if !strings.Contains(req.RawPayload, "Host: target-node.internal") {
		t.Errorf("expected payload to contain target host header")
	}
}

func TestBuildFrontedRequestInvalid(t *testing.T) {
	cfg := DomainFrontingConfig{
		FrontDomain: "",
	}
	_, err := BuildFrontedRequest(cfg, "GET")
	if err == nil {
		t.Errorf("expected error on empty front domain")
	}
}
