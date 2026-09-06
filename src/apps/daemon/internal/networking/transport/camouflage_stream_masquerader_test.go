package transport

import (
	"testing"
)

func TestCamouflageStreamMasquerader(t *testing.T) {
	secret := []byte("my_super_secret_seed")
	masq := NewCamouflageStreamMasquerader(secret, "www.bing.com")
	uid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	masq.RegisterUser(uid)

	preamble := masq.GeneratePreamble(uid)
	act := masq.InspectInboundStream(preamble)
	if act != ProbeActionAcceptStream {
		t.Fatalf("expected accept stream, got %s", act)
	}

	invalidPreamble := make([]byte, 32)
	act = masq.InspectInboundStream(invalidPreamble)
	if act != ProbeActionDeflectToDecoy {
		t.Fatalf("expected deflect to decoy, got %s", act)
	}

	if masq.DecoyHost() != "www.bing.com" {
		t.Fatalf("expected decoy host www.bing.com, got %s", masq.DecoyHost())
	}
}
