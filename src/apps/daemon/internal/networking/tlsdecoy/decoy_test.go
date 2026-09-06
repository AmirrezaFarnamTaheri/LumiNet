package tlsdecoy

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestBuildPaddedClientHelloStructureAndBound(t *testing.T) {
	for _, sni := range []string{
		"security.vercel.com",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 27),
	} {
		hello, err := BuildPaddedClientHello(sni)
		if err != nil {
			t.Fatal(err)
		}
		if len(hello) != ClientHelloSize {
			t.Fatalf("len=%d", len(hello))
		}
		if hello[0] != 0x16 || hello[5] != 0x01 {
			t.Fatal("not a TLS ClientHello")
		}
		if got := int(binary.BigEndian.Uint16(hello[3:5])); got != len(hello)-5 {
			t.Fatalf("record len=%d", got)
		}
		if got := int(hello[6])<<16 | int(hello[7])<<8 | int(hello[8]); got != len(hello)-9 {
			t.Fatalf("handshake len=%d", got)
		}
		if got := int(binary.BigEndian.Uint16(hello[125:127])); got != len(sni) {
			t.Fatalf("sni len=%d", got)
		}
		if got := string(hello[127 : 127+len(sni)]); got != sni {
			t.Fatalf("sni=%q", got)
		}
	}
}

func TestValidSNIRejectsMalformedNames(t *testing.T) {
	for _, sni := range []string{"", "bad name", "-bad.example", "bad-.example", ".bad.example", "bad.example.", strings.Repeat("x", 220), "tést.example"} {
		if ValidSNI(sni) {
			t.Fatalf("unexpected valid SNI %q", sni)
		}
		if _, err := BuildPaddedClientHello(sni); err == nil {
			t.Fatalf("builder accepted %q", sni)
		}
	}
}
