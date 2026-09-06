package dns

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestValidateDoTEndpoint(t *testing.T) {
	if err := validateDoTEndpoint(DoTEndpoint{Address: "1.1.1.1:853", ServerName: "cloudflare-dns.com"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []DoTEndpoint{
		{Address: "1.1.1.1:53", ServerName: "cloudflare-dns.com"},
		{Address: "1.1.1.1:853"},
		{Address: "1.1.1.1:853", ServerName: "dns.google\nSocksPort 1"},
	} {
		if err := validateDoTEndpoint(bad); err == nil {
			t.Fatalf("invalid endpoint accepted: %+v", bad)
		}
	}
}

func TestDoTDialRejectsNonSOCKSProxyBeforeNetwork(t *testing.T) {
	r := NewResolver("127.0.0.1:0", "")
	r.ProxyURL = "http://127.0.0.1:8080"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := r.dialDoTRaw(ctx, "127.0.0.1:853", time.Second); err == nil {
		t.Fatal("non-SOCKS DoT proxy unexpectedly accepted")
	}
}

func TestConfigureDoHProxyFailsClosed(t *testing.T) {
	for _, raw := range []string{"ftp://127.0.0.1:21", "://bad", "http://"} {
		r := NewResolver("127.0.0.1:0", "")
		r.ProxyURL = raw
		if err := r.configureDoHProxy(&http.Transport{}); err == nil {
			t.Fatalf("invalid DoH proxy %q accepted", raw)
		}
	}
	for _, raw := range []string{"socks5://127.0.0.1:9050", "http://127.0.0.1:8080"} {
		r := NewResolver("127.0.0.1:0", "")
		r.ProxyURL = raw
		if err := r.configureDoHProxy(&http.Transport{}); err != nil {
			t.Fatalf("valid DoH proxy %q rejected: %v", raw, err)
		}
	}
}

func TestLookupEncryptedARejectsUnsafeNamesBeforeNetwork(t *testing.T) {
	r := NewResolver("127.0.0.1:0", "")
	for _, name := range []string{"", "1.2.3.4", "bad/name", "bad\\name", "bad\nname"} {
		if _, err := r.LookupEncryptedA(context.Background(), name); err == nil {
			t.Fatalf("unsafe diagnostic name %q accepted", name)
		}
	}
}
