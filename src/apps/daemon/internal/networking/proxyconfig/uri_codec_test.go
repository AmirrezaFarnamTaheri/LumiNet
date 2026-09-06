package proxyconfig

import (
	"testing"
)

func TestProxyUriCodec(t *testing.T) {
	codec := &ProxyUriCodec{}
	uri := "vless://user-uuid-123@node1.net:443?encryption=none&security=tls&sni=node1.net#MyNode"
	parsed, err := codec.Parse(uri)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.Protocol != "vless" || parsed.Address != "node1.net" || parsed.Port != 443 {
		t.Fatalf("mismatched parsed fields: %+v", parsed)
	}

	serialized := codec.Serialize(parsed)
	parsed2, err := codec.Parse(serialized)
	if err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
	if parsed2.Address != parsed.Address || parsed2.Port != parsed.Port {
		t.Fatalf("roundtrip mismatch")
	}
}
