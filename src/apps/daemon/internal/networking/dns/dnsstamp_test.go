package dns

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseServerStampDoH(t *testing.T) {
	// Hand-built DoH stamp: props(no-log|dnssec), addr "8.8.8.8:443",
	// one 32-byte hash, provider "dns.google", path "/dns-query".
	var bin []byte
	bin = append(bin, 0x02)
	var props uint64 = uint64(ServerInformalPropertyNoLog | ServerInformalPropertyDNSSEC)
	bin = binary.LittleEndian.AppendUint64(bin, props)
	addr := []byte("8.8.8.8:443")
	bin = append(bin, byte(len(addr)))
	bin = append(bin, addr...)
	hash := make([]byte, 32)
	hash[0] = 0xAB
	bin = append(bin, 32) // final vlp entry: no continuation bit
	bin = append(bin, hash...)
	prov := []byte("dns.google")
	bin = append(bin, byte(len(prov)))
	bin = append(bin, prov...)
	path := []byte("/dns-query")
	bin = append(bin, byte(len(path)))
	bin = append(bin, path...)

	stamp, err := ParseServerStamp(StampScheme + base64.RawURLEncoding.EncodeToString(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if stamp.Proto != StampProtoTypeDoH {
		t.Fatalf("proto = %v", stamp.Proto)
	}
	if stamp.ServerAddrStr != "8.8.8.8:443" {
		t.Fatalf("addr = %q", stamp.ServerAddrStr)
	}
	if stamp.ProviderName != "dns.google" || stamp.Path != "/dns-query" {
		t.Fatalf("provider/path = %q/%q", stamp.ProviderName, stamp.Path)
	}
	if len(stamp.Hashes) != 1 || stamp.Hashes[0][0] != 0xAB {
		t.Fatalf("hashes = %v", stamp.Hashes)
	}
	if stamp.Props != ServerInformalPropertyNoLog|ServerInformalPropertyDNSSEC {
		t.Fatalf("props = %v", stamp.Props)
	}
}

func TestParseServerStampDoHWithBootstrap(t *testing.T) {
	var bin []byte
	bin = append(bin, 0x02)
	bin = binary.LittleEndian.AppendUint64(bin, 0)
	addr := []byte("1.1.1.1:443")
	bin = append(bin, byte(len(addr)))
	bin = append(bin, addr...)
	bin = append(bin, 0x00) // zero-length, no continuation bit: ends hash list
	prov := []byte("cloudflare-dns.com")
	bin = append(bin, byte(len(prov)))
	bin = append(bin, prov...)
	path := []byte("/dns-query")
	bin = append(bin, byte(len(path)))
	bin = append(bin, path...)
	boot := []byte("1.0.0.1:443")
	bin = append(bin, byte(len(boot))) // final bootstrap: no continuation bit
	bin = append(bin, boot...)

	stamp, err := ParseServerStamp(StampScheme + base64.RawURLEncoding.EncodeToString(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(stamp.BootstrapIPs) != 1 || stamp.BootstrapIPs[0] != "1.0.0.1:443" {
		t.Fatalf("bootstrap = %v", stamp.BootstrapIPs)
	}
}

func TestParseServerStampDNSCrypt(t *testing.T) {
	var bin []byte
	bin = append(bin, 0x01)
	bin = binary.LittleEndian.AppendUint64(bin, uint64(ServerInformalPropertyNoFilter))
	addr := []byte("9.9.9.9:5443")
	bin = append(bin, byte(len(addr)))
	bin = append(bin, addr...)
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(i)
	}
	bin = append(bin, byte(len(pk)))
	bin = append(bin, pk...)
	prov := []byte("2.dnscrypt-cert.example.com")
	bin = append(bin, byte(len(prov)))
	bin = append(bin, prov...)

	stamp, err := ParseServerStamp(StampScheme + base64.RawURLEncoding.EncodeToString(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if stamp.Proto != StampProtoTypeDNSCrypt {
		t.Fatalf("proto = %v", stamp.Proto)
	}
	if len(stamp.ServerPk) != 32 {
		t.Fatalf("pk len = %d", len(stamp.ServerPk))
	}
}

func TestParseServerStampDNSCryptDefaultPort(t *testing.T) {
	// Addr without a port gets the default 443 (upstream behaviour).
	var bin []byte
	bin = append(bin, 0x01)
	bin = binary.LittleEndian.AppendUint64(bin, 0)
	addr := []byte("9.9.9.9")
	bin = append(bin, byte(len(addr)))
	bin = append(bin, addr...)
	bin = append(bin, 32)
	bin = append(bin, make([]byte, 32)...)
	prov := []byte("2.dnscrypt-cert.example.com")
	bin = append(bin, byte(len(prov)))
	bin = append(bin, prov...)

	stamp, err := ParseServerStamp(StampScheme + base64.RawURLEncoding.EncodeToString(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if stamp.ServerAddrStr != "9.9.9.9:443" {
		t.Fatalf("addr = %q, want default port appended", stamp.ServerAddrStr)
	}
}

func TestParseServerStampPlain(t *testing.T) {
	var bin []byte
	bin = append(bin, 0x00)
	bin = binary.LittleEndian.AppendUint64(bin, 0)
	addr := []byte("127.0.0.1") // portless -> :53 for plain
	bin = append(bin, byte(len(addr)))
	bin = append(bin, addr...)

	stamp, err := ParseServerStamp(StampScheme + base64.RawURLEncoding.EncodeToString(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if stamp.Proto != StampProtoTypePlain || stamp.ServerAddrStr != "127.0.0.1:53" {
		t.Fatalf("plain stamp = %+v", stamp)
	}
}

func TestParseServerStampRelay(t *testing.T) {
	var bin []byte
	bin = append(bin, 0x81)
	addr := []byte("9.9.9.9:443")
	bin = append(bin, byte(len(addr)))
	bin = append(bin, addr...)

	stamp, err := ParseServerStamp(StampScheme + base64.RawURLEncoding.EncodeToString(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if stamp.Proto != StampProtoTypeDNSCryptRelay {
		t.Fatalf("proto = %v", stamp.Proto)
	}
}

func TestParseServerStampRejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"http://example.com",
		"sdns://",
		"sdns://!!!!",
		// DoH with a non-32-byte hash
		func() string {
			var bin []byte
			bin = append(bin, 0x02)
			bin = binary.LittleEndian.AppendUint64(bin, 0)
			addr := []byte("1.1.1.1:443")
			bin = append(bin, byte(len(addr)))
			bin = append(bin, addr...)
			bin = append(bin, 0x80|8)
			bin = append(bin, make([]byte, 8)...)
			prov := []byte("cloudflare-dns.com")
			bin = append(bin, byte(len(prov)))
			bin = append(bin, prov...)
			path := []byte("/dns-query")
			bin = append(bin, byte(len(path)))
			bin = append(bin, path...)
			return StampScheme + base64.RawURLEncoding.EncodeToString(bin)
		}(),
	}
	for i, tc := range cases {
		if tc == "" {
			continue
		}
		if _, err := ParseServerStamp(tc); err == nil {
			t.Errorf("case %d (%q): expected error", i, tc)
		}
	}
	// Prefix check: not-sdns must fail with the prefix error.
	if _, err := ParseServerStamp("http://example.com"); err != nil && !strings.Contains(err.Error(), "sdns") {
		t.Errorf("unexpected prefix error: %v", err)
	}
}

func TestParseServerStampListMixedFeed(t *testing.T) {
	// Build one valid DoH stamp and prepend/append non-stamp lines plus
	// a deliberately malformed stamp. The batch parser must return one
	// ServerStamp and exactly one StampParseError at the malformed line.
	dohBin := []byte{0x02}
	dohBin = binary.LittleEndian.AppendUint64(dohBin, 0)
	addr := []byte("9.9.9.9:443")
	dohBin = append(dohBin, byte(len(addr)))
	dohBin = append(dohBin, addr...)
	dohBin = append(dohBin, 0x00) // zero-length hash list
	prov := []byte("dns.quad9.net")
	dohBin = append(dohBin, byte(len(prov)))
	dohBin = append(dohBin, prov...)
	path := []byte("/dns-query")
	dohBin = append(dohBin, byte(len(path)))
	dohBin = append(dohBin, path...)
	good := StampScheme + base64.RawURLEncoding.EncodeToString(dohBin)

	body := "# comment line\n\n" + good + "\nsdns://@@@\nplain text line\n"
	stamps, errs := ParseServerStampList(body)
	if len(stamps) != 1 {
		t.Fatalf("stamps=%d want 1", len(stamps))
	}
	if stamps[0].Proto != StampProtoTypeDoH {
		t.Fatalf("proto=%v", stamps[0].Proto)
	}
	if len(errs) != 1 {
		t.Fatalf("errs=%d want 1", len(errs))
	}
	if errs[0].Line != 4 {
		t.Fatalf("error line=%d want 4", errs[0].Line)
	}
}

func TestNewDNSCryptServerStampFromLegacy(t *testing.T) {
	pk := strings.Repeat("ab", 32)
	stamp, err := NewDNSCryptServerStampFromLegacy("9.9.9.9", pk, "dns.quad9.net", ServerInformalPropertyNoLog)
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	if stamp.ServerAddrStr != "9.9.9.9:443" {
		t.Fatalf("addr = %q", stamp.ServerAddrStr)
	}
	if len(stamp.ServerPk) != 32 {
		t.Fatalf("pk = %d bytes", len(stamp.ServerPk))
	}
	if _, err := NewDNSCryptServerStampFromLegacy("9.9.9.9", "zz", "x", 0); err == nil {
		t.Fatal("expected invalid-pk error")
	}
}


// FuzzParseServerStamp (roadmap item 10): the sdns:// decoder is exposed
// to attacker-influenced subscription content, so every byte is fair
// game. The only contract: no panic. Run with:
//   go test -fuzz=FuzzParseServerStamp -fuzztime=60s ./internal/networking/dns/
func FuzzParseServerStamp(f *testing.F) {
	f.Add("sdns://AQcAAAAAAAAADzkuOS45LjkAOjpBQUFBQUE")
	f.Add("sdns://!!!")
	f.Add("sdns://")
	f.Add("sdns://A")
	f.Add("")
	f.Add("not-a-stamp")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseServerStamp(s)
		stamps, errs := ParseServerStampList(s)
		// Invariant: every stamp that came back must be re-parseable
		// (round-trip stability of the binary decoder).
		for _, st := range stamps {
			if st.Proto > 0x85 {
				t.Fatalf("impossible proto %d from %q", st.Proto, s)
			}
		}
		for _, e := range errs {
			if e.Err == nil {
				t.Fatal("nil error recorded in batch parse errors")
			}
		}
	})
}
