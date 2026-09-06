package proxyconfig

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestPostRefactor224RejectsAmbiguousMultiAuthorityAndPreservesIPv6(t *testing.T) {
	bad := []string{
		"vless://11111111-1111-1111-1111-111111111111@one.example,two.example:443?type=tcp",
		"trojan://secret@one.example two.example:443",
		"kcp://secret@one.example,two.example:29900",
	}
	for _, uri := range bad {
		if _, err := ParseProxyURI(uri); err == nil || !strings.Contains(err.Error(), "multi-authority") {
			t.Fatalf("ParseProxyURI(%q) err=%v, want multi-authority rejection", uri, err)
		}
	}

	cfg, err := ParseProxyURI("vless://11111111-1111-1111-1111-111111111111@[2001:db8::1]:443?type=tcp")
	if err != nil {
		t.Fatalf("bracketed IPv6 rejected: %v", err)
	}
	if cfg.Address != "2001:db8::1" {
		t.Fatalf("IPv6 address=%q", cfg.Address)
	}
}

func TestPostRefactor224KCPExplicitZeroFalseRoundTrip(t *testing.T) {
	uri := "kcp://secret@example.com:29900?profile=loss-recovery&loss=35&data_shards=0&parity_shards=0&nodelay=0&acknodelay=false&writedelay=false&dscp=0&dup=0&rate=0&jitter=false"
	first, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if !first.KCPDataShardsSet || !first.KCPParityShardsSet || !first.KCPNoDelaySet || !first.KCPACKNoDelaySet || !first.KCPWriteDelaySet || !first.KCPDSCPSet || !first.KCPPacketDuplicationSet || !first.KCPRateLimitSet || !first.KCPJitterSet {
		t.Fatalf("explicit-set metadata lost after parse: %+v", first)
	}
	encoded := first.ToURI()
	second, err := ParseProxyURI(encoded)
	if err != nil {
		t.Fatalf("reparse %q: %v", encoded, err)
	}
	if second.KCPDataShards != 0 || second.KCPParityShards != 0 || second.KCPNoDelay != 0 || second.KCPACKNoDelay || second.KCPWriteDelay || second.KCPDSCP != 0 || second.KCPPacketDuplication != 0 || second.KCPRateLimitBPS != 0 || second.KCPJitter {
		t.Fatalf("explicit zero/false values drifted: %+v", second)
	}
	if !second.KCPDataShardsSet || !second.KCPParityShardsSet || !second.KCPNoDelaySet || !second.KCPACKNoDelaySet || !second.KCPWriteDelaySet || !second.KCPDSCPSet || !second.KCPPacketDuplicationSet || !second.KCPRateLimitSet || !second.KCPJitterSet {
		t.Fatalf("explicit-set metadata lost after round trip: %+v", second)
	}
}

func TestPostRefactor224CredentialFreeProxyFormatCorpus(t *testing.T) {
	vmessPayload := `{"v":"2","ps":"fixture","add":"example.com","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":"0","net":"tcp","type":"none","host":"","path":"","tls":"tls"}`
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessPayload))
	cases := []struct {
		name string
		uri  string
		want ProxyProtocol
	}{
		{"vmess", vmess, ProtocolVMess},
		{"vless-reality", "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd", ProtocolVLESS},
		{"trojan", "trojan://fixture-secret@example.com:443?sni=example.com", ProtocolTrojan},
		{"shadowsocks", "ss://YWVzLTEyOC1nY206Zml4dHVyZS1zZWNyZXQ=@example.com:8388", ProtocolShadowsocks},
		{"hysteria2", "hysteria2://fixture-secret@example.com:443?sni=example.com", ProtocolHysteria2},
		{"tuic", "tuic://11111111-1111-1111-1111-111111111111:fixture-secret@example.com:443?sni=example.com", ProtocolTUIC},
		{"juicity", "juicity://11111111-1111-1111-1111-111111111111:fixture-secret@example.com:443?sni=example.com", ProtocolJuicity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseProxyURI(tc.uri)
			if err != nil {
				t.Fatalf("ParseProxyURI(%q): %v", tc.uri, err)
			}
			if cfg.Protocol != tc.want {
				t.Fatalf("protocol=%q want=%q", cfg.Protocol, tc.want)
			}
		})
	}
}

func TestPostRefactor224KCPAESGCMMethodRoundTrip(t *testing.T) {
	first, err := ParseProxyURI("kcp://secret@example.com:29900?crypt=aes-gcm")
	if err != nil {
		t.Fatal(err)
	}
	if first.Method != "aes-gcm" {
		t.Fatalf("method=%q", first.Method)
	}
	uri := first.ToURI()
	second, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if second.Method != "aes-gcm" {
		t.Fatalf("round-trip method=%q uri=%q", second.Method, uri)
	}
}

func TestPostRefactor224StandardSingleAuthorityRegressionCases(t *testing.T) {
	cases := []string{
		"trojan://fixture-secret@single.example:443?sni=single.example",
		"vless://11111111-1111-1111-1111-111111111111@[2001:db8::2]:443?type=tcp",
		"kcp://fixture-secret@single.example:29900?crypt=aes",
	}
	for _, uri := range cases {
		if _, err := ParseProxyURI(uri); err != nil {
			t.Fatalf("single-authority regression for %q: %v", uri, err)
		}
	}
}

func TestPostRefactor224LibXrayProtocolShapeSubset(t *testing.T) {
	cases := []struct {
		uri  string
		want ProxyProtocol
	}{
		{"vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd", ProtocolVLESS},
		{"trojan://fixture-secret@example.com:443?sni=example.com", ProtocolTrojan},
		{"hysteria2://fixture-secret@example.com:443?sni=example.com", ProtocolHysteria2},
	}
	for _, tc := range cases {
		cfg, err := ParseProxyURI(tc.uri)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.uri, err)
		}
		if cfg.Protocol != tc.want {
			t.Fatalf("protocol=%q want=%q", cfg.Protocol, tc.want)
		}
	}
}

func TestPostRefactor224ShareLinkParsersRoundTripCredentialFreeSamples(t *testing.T) {
	cases := []string{
		"trojan://fixture-secret@example.com:443?sni=example.com",
		"hysteria2://fixture-secret@example.com:443?sni=example.com",
		"kcp://fixture-secret@example.com:29900?crypt=aes-gcm&profile=balanced",
	}
	for _, uri := range cases {
		first, err := ParseProxyURI(uri)
		if err != nil {
			t.Fatalf("parse %q: %v", uri, err)
		}
		encoded := first.ToURI()
		second, err := ParseProxyURI(encoded)
		if err != nil {
			t.Fatalf("reparse %q: %v", encoded, err)
		}
		if second.Protocol != first.Protocol || second.Address != first.Address || second.Port != first.Port {
			t.Fatalf("round trip drift first=%+v second=%+v", first, second)
		}
	}
}
