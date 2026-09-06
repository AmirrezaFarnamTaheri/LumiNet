package updateadmission

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoverFetchesBoundedEnvelope(t *testing.T) {
	want := Envelope{KeyID: "primary", Payload: "cGF5bG9hZA==", Signature: "c2ln"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer server.Close()
	got, err := Discover(context.Background(), server.Client(), server.URL+"/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got=%+v want=%+v", got, want)
	}
}

func TestDiscoverRejectsUnsafeOrOversizedResponses(t *testing.T) {
	if _, err := Discover(context.Background(), nil, "http://example.test/manifest.json"); err == nil {
		t.Fatal("HTTP discovery URL accepted")
	}
	oversized := strings.Repeat("x", int(maxDiscoveryResponseBytes)+1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(oversized))
	}))
	defer server.Close()
	if _, err := Discover(context.Background(), server.Client(), server.URL); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response accepted: %v", err)
	}
}

func TestDiscoverRejectsUnknownFieldsAndInsecureRedirect(t *testing.T) {
	for _, handler := range []http.HandlerFunc{
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"key_id":"k","payload":"p","signature":"s","extra":true}`))
		},
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://example.test/manifest", http.StatusFound)
		},
	} {
		server := httptest.NewTLSServer(handler)
		if _, err := Discover(context.Background(), server.Client(), server.URL); err == nil {
			server.Close()
			t.Fatal("invalid discovery response accepted")
		}
		server.Close()
	}
}
