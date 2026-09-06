package security

import (
	"testing"
)

func TestEdnsScrubber(t *testing.T) {
	scrubber := NewEdnsScrubber(24, 56, false)
	masked := scrubber.MaskIPv4("192.168.1.150")
	if masked != "192.168.1.0" {
		t.Fatalf("expected 192.168.1.0, got %s", masked)
	}

	rawPkt := make([]byte, 12)
	rawPkt[0] = 0xAB
	rawPkt[1] = 0xCD
	scrubbed, err := scrubber.ScrubPacket(rawPkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scrubbed) != 12 || scrubbed[0] != 0xAB {
		t.Fatalf("invalid scrubbed output")
	}
}
