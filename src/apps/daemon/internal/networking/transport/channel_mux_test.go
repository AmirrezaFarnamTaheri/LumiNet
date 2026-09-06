package transport

import (
	"bytes"
	"testing"
)

func TestChannelMuxFrameRoundTrip(t *testing.T) {
	frame := &ChannelMuxFrame{
		ChannelID: 101,
		Opcode:    OpChannelData,
		Payload:   []byte("multiplexed stream chunk"),
	}

	var buf bytes.Buffer
	if err := frame.Encode(&buf); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decoded, err := DecodeChannelMuxFrame(&buf)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if decoded.ChannelID != 101 || decoded.Opcode != OpChannelData || !bytes.Equal(decoded.Payload, frame.Payload) {
		t.Fatal("decoded frame does not match")
	}

	mux := NewTransparentChannelMux()
	session := mux.OpenChannel()
	if err := mux.RoutePayload(session.ID, []byte("data1")); err != nil {
		t.Fatalf("RoutePayload failed: %v", err)
	}
	received := <-session.InboundCh
	if !bytes.Equal(received, []byte("data1")) {
		t.Fatal("unexpected channel payload received")
	}
	mux.CloseChannel(session.ID)
}
