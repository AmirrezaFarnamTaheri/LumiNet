package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestEchClientHelloGeneration(t *testing.T) {
	// Base64 ECH Config List representing a mock ECH config
	echConfigB64 := "AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA"

	configs, err := ParseECHConfigList(echConfigB64)
	if err != nil {
		t.Fatalf("ParseECHConfigList failed: %v", err)
	}

	if len(configs) == 0 {
		t.Fatal("Expected at least one ECHConfig")
	}

	cfg := configs[0]
	if cfg.PublicName != "public.tls-ech.dev" {
		t.Errorf("Got PublicName %q, want %q", cfg.PublicName, "public.tls-ech.dev")
	}

	if cfg.Version != 0xfe0d {
		t.Errorf("Got version 0x%04x, want 0xfe0d", cfg.Version)
	}

	// Test cache expiration
	cache := &ECHKeyCache{
		Base64Config: echConfigB64,
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // expired
	}
	if !cache.IsExpired() {
		t.Error("Expected cache to be expired")
	}

	cache2 := &ECHKeyCache{
		Base64Config: echConfigB64,
		ExpiresAt:    time.Now().Add(1 * time.Hour), // active
	}
	if cache2.IsExpired() {
		t.Error("Expected cache NOT to be expired")
	}
}

func TestEchFallbackFronting(t *testing.T) {
	originalVerify := ECHInsecureSkipVerify
	defer func() { ECHInsecureSkipVerify = originalVerify }()
	// The httptest server uses a synthetic local certificate. Explicitly opt into
	// insecure verification for this fixture instead of relying on production defaults.
	ECHInsecureSkipVerify = true

	// Spin up local HTTP/TLS server (doesn't speak ECH, but serves as fallback target)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	u := ts.URL
	u = strings.TrimPrefix(u, "https://")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialFallbackFronting(ctx, "tcp", u, "127.0.0.1", "localhost")
	if err != nil {
		t.Fatalf("Fallback fronting failed: %v", err)
	}
	conn.Close()
}

func TestEchClientCertValidation(t *testing.T) {
	if ECHInsecureSkipVerify {
		t.Fatal("ECH certificate verification must be enabled by default")
	}
}

func TestIsCloudflareIP(t *testing.T) {
	if !IsCloudflareIP(net.ParseIP("104.16.0.1")) {
		t.Error("Expected 104.16.0.1 to be Cloudflare IP")
	}
	if IsCloudflareIP(net.ParseIP("8.8.8.8")) {
		t.Error("Expected 8.8.8.8 NOT to be Cloudflare IP")
	}
}

func TestResolveECHViaDoH(t *testing.T) {
	// Mock DoH Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")

		body, _ := io.ReadAll(r.Body)
		reqMsg := new(dns.Msg)
		_ = reqMsg.Unpack(body)

		respMsg := new(dns.Msg)
		respMsg.SetReply(reqMsg)

		hdr := dns.RR_Header{
			Name:   reqMsg.Question[0].Name,
			Rrtype: dns.TypeHTTPS,
			Class:  dns.ClassINET,
			Ttl:    60,
		}

		svcOption := &dns.SVCBECHConfig{
			ECH: []byte("mock-ech-key-data"),
		}

		https := &dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr:      hdr,
				Priority: 1,
				Target:   ".",
				Value:    []dns.SVCBKeyValue{svcOption},
			},
		}

		respMsg.Answer = append(respMsg.Answer, https)
		respBuf, _ := respMsg.Pack()
		_, _ = w.Write(respBuf)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ech, err := ResolveECHViaDoH(ctx, "example.com", ts.URL)
	if err != nil {
		t.Fatalf("ResolveECHViaDoH failed: %v", err)
	}

	if string(ech) != "mock-ech-key-data" {
		t.Errorf("Expected 'mock-ech-key-data', got %q", string(ech))
	}
}
