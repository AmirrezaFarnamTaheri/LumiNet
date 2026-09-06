package proxy

import (
	"testing"
)

func TestHeaderInterceptRouter(t *testing.T) {
	router := NewHeaderInterceptRouter()
	router.AddRule("x-telepresence-intercept-id", "dev-alice", "127.0.0.1:9090")

	normal := map[string]string{"User-Agent": "curl/7.68.0"}
	if _, matched := router.EvaluateHeaders(normal); matched {
		t.Fatal("normal traffic should not match")
	}

	dev := map[string]string{"X-Telepresence-Intercept-Id": "dev-alice"}
	target, matched := router.EvaluateHeaders(dev)
	if !matched || target != "127.0.0.1:9090" {
		t.Fatalf("expected 127.0.0.1:9090, got %s (matched=%v)", target, matched)
	}
}
