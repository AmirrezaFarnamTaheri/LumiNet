package diagnostics

import (
	"net/url"
	"testing"
)

func TestValidOnionV3HostAndStableAffinity(t *testing.T) {
	host := "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
	if len(host[:len(host)-6]) != 56 {
		t.Fatalf("fixture label length wrong")
	}
	if !ValidOnionV3Host(host) {
		t.Fatalf("expected valid v3 onion")
	}
	if ValidOnionV3Host("short.onion") {
		t.Fatal("accepted invalid onion")
	}
	endpoints := []string{"127.0.0.1:9050", "socks5://127.0.0.1:9150", "127.0.0.1:9050"}
	a, err := StableProxyForOnion(host, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	b, err := StableProxyForOnion(host, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("affinity unstable: %q != %q", a, b)
	}
}

func TestExtractOnionHTMLMetadataCountsOnlyV3OnionLinks(t *testing.T) {
	base, err := url.Parse("http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion/start")
	if err != nil {
		t.Fatal(err)
	}
	other := "bcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxy.onion"
	body := []byte(`<html><head><title> Hidden Service </title><meta name="description" content="sample description"></head><body><a href="/same">same</a><a href="http://` + other + `/other">other</a><a href="https://example.com/">clear</a></body></html>`)
	title, description, onionLinks, same := extractOnionHTMLMetadata(body, base)
	if title != "Hidden Service" || description != "sample description" || onionLinks != 2 || same != 1 {
		t.Fatalf("metadata=(%q,%q,%d,%d)", title, description, onionLinks, same)
	}
}
