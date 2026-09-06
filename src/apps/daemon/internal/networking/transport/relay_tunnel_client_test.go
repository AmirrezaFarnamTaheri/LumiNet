package transport

import (
	"testing"
)

func TestRelayTunnelClientConnectRequest(t *testing.T) {
	cfg := RelayTunnelClientConfig{
		RelayEndpoint: "https://relay.edge.luminet.network:8443",
		AuthToken:     "relay-secret-99",
		TargetHost:    "1.1.1.1",
		TargetPort:    443,
	}

	client, err := NewRelayTunnelClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	req, err := client.BuildConnectRequest()
	if err != nil {
		t.Fatalf("failed to build connect request: %v", err)
	}

	if req.Host != "1.1.1.1:443" {
		t.Errorf("expected host 1.1.1.1:443, got %s", req.Host)
	}
	if req.Header.Get("Proxy-Authorization") != "Bearer relay-secret-99" {
		t.Errorf("unexpected proxy-authorization header")
	}
}
