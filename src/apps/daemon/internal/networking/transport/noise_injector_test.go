package transport

import (
	"bytes"
	"testing"
)

func TestNoisePacketInjector(t *testing.T) {
	inj := NewNoisePacketInjector(DefaultNoisePattern())
	frame := inj.SynthesizeNoiseFrame(12345)

	if len(frame) < 13 {
		t.Fatalf("frame too short: %d", len(frame))
	}
	if !bytes.Equal(frame[0:3], []byte{0x17, 0x03, 0x03}) {
		t.Fatal("invalid magic header")
	}
}
