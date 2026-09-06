package ipscanner

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTargetAddressSupportsIPv4IPv6AndHostnames(t *testing.T) {
	tests := []struct {
		host string
		port int
		want string
	}{
		{host: "192.0.2.25", port: 443, want: "192.0.2.25:443"},
		{host: "2001:db8::25", port: 443, want: "[2001:db8::25]:443"},
		{host: "example.test", port: 8443, want: "example.test:8443"},
	}
	for _, test := range tests {
		if got := targetAddress(test.host, test.port); got != test.want {
			t.Errorf("targetAddress(%q, %d) = %q, want %q", test.host, test.port, got, test.want)
		}
	}
}

func TestTCPProbeHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scanner := NewScanner(DefaultScanConfig())
	_, err := scanner.tcpPing(ctx, "192.0.2.1", 443)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("tcpPing() error = %v, want context cancellation", err)
	}
}

func TestDefaultScanConfigDoesNotAlterTrafficOrSkipVerification(t *testing.T) {
	config := DefaultScanConfig()
	if config.EnableUDPNoise {
		t.Fatal("default scan configuration enables UDP noise")
	}
	if config.AllowInsecureTLS {
		t.Fatal("default scan configuration skips TLS verification")
	}
}

func TestTLSVerificationRequiresExplicitObservationOverride(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	address := server.Listener.Addr().(*net.TCPAddr)

	strict := NewScanner(DefaultScanConfig())
	if _, err := strict.tlsHandshake(context.Background(), address.IP.String(), address.Port, "example.test"); err == nil {
		t.Fatal("strict TLS probe accepted an untrusted test certificate")
	}

	config := DefaultScanConfig()
	config.AllowInsecureTLS = true
	observer := NewScanner(config)
	if _, err := observer.tlsHandshake(context.Background(), address.IP.String(), address.Port, "example.test"); err != nil {
		t.Fatalf("explicit observation TLS probe failed: %v", err)
	}
}
