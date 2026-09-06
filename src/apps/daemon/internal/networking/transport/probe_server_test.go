package transport

import (
	"testing"
)

func TestEmbeddedProbeServer(t *testing.T) {
	srv := NewEmbeddedProbeServer("127.0.0.1", 9090)
	srv.SetAuth("admin", "secret123")
	srv.RegisterPayload("/profile.ovpn", []byte("sample_ovpn_content"))

	res1 := srv.HandleRequest("GET", "/health", "", "")
	if res1.StatusCode != 401 {
		t.Fatalf("expected 401 unauthorized, got %d", res1.StatusCode)
	}

	res2 := srv.HandleRequest("GET", "/health", "Basic admin:secret123", "")
	if res2.StatusCode != 200 || string(res2.Body) != "OK" {
		t.Fatalf("expected 200 OK, got %d", res2.StatusCode)
	}

	res3 := srv.HandleRequest("GET", "/profile.ovpn", "Basic admin:secret123", "bytes=0-5")
	if res3.StatusCode != 206 || string(res3.Body) != "sample" {
		t.Fatalf("expected 206 partial content 'sample', got %d: %s", res3.StatusCode, string(res3.Body))
	}
}
