package sub

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	dnsnet "github.com/maybeknott/luminet/internal/networking/dns"
)

// buildDoHStamp hand-builds one DoH stamp (props no-log|dnssec, addr
// "8.8.8.8:443", one 32-byte hash, provider "dns.google", path
// "/dns-query") — the same construction used in the networking/dns
// dnsstamp tests, so both layers verify against identical fixtures.
func buildDoHStamp(t *testing.T) string {
	t.Helper()
	var bin []byte
	bin = append(bin, 0x02)
	var props uint64 = uint64(dnsnet.ServerInformalPropertyNoLog | dnsnet.ServerInformalPropertyDNSSEC)
	bin = binary.LittleEndian.AppendUint64(bin, props)
	addr := []byte("8.8.8.8:443")
	bin = append(bin, byte(len(addr)))
	bin = append(bin, addr...)
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	bin = append(bin, byte(len(hash)))
	bin = append(bin, hash...)
	provider := []byte("dns.google")
	bin = append(bin, byte(len(provider)))
	bin = append(bin, provider...)
	path := []byte("/dns-query")
	bin = append(bin, byte(len(path)))
	bin = append(bin, path...)
	return dnsnet.StampScheme + base64.RawURLEncoding.EncodeToString(bin)
}

func TestParseStampFeedMixed(t *testing.T) {
	good := buildDoHStamp(t)
	body := "# comment line\n\n" + good + "\nsdns://@@@\nplain text line\n"
	res := ParseStampFeed(body)
	if len(res.Resolvers) != 1 {
		t.Fatalf("resolvers = %d, want 1", len(res.Resolvers))
	}
	r := res.Resolvers[0]
	if r.Proto != "DoH" {
		t.Fatalf("proto = %q", r.Proto)
	}
	if r.Addr != "8.8.8.8:443" {
		t.Fatalf("addr = %q", r.Addr)
	}
	if r.ProviderName != "dns.google" {
		t.Fatalf("provider = %q", r.ProviderName)
	}
	if r.Path != "/dns-query" {
		t.Fatalf("path = %q", r.Path)
	}
	if len(r.Hashes) != 1 || len(r.Hashes[0]) != 64 {
		t.Fatalf("hashes = %v", r.Hashes)
	}
	// The malformed sdns://@@@ must surface as an issue with line 4.
	if len(res.Issues) != 1 || res.Issues[0].Line != 4 {
		t.Fatalf("issues = %+v", res.Issues)
	}
}

func TestParseStampFeedEmptyAndGarbage(t *testing.T) {
	for _, body := range []string{"", "\n\n", "no stamps here", "# only comments\n"} {
		res := ParseStampFeed(body)
		if len(res.Resolvers) != 0 || len(res.Issues) != 0 {
			t.Fatalf("body %q: resolvers=%d issues=%d", body, len(res.Resolvers), len(res.Issues))
		}
	}
}
