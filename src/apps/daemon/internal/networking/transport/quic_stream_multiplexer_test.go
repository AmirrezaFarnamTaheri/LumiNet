package transport

import (
	"bytes"
	"testing"
)

func TestQuicStreamMultiplexer(t *testing.T) {
	mux := NewQuicStreamMultiplexer(65536)
	s0 := mux.OpenStream(QuicClientBidi)
	if s0 != 0 {
		t.Fatalf("expected stream ID 0, got %d", s0)
	}

	frame1, err := mux.WriteStreamData(s0, []byte("Hello "), false)
	if err != nil {
		t.Fatalf("write frame1 failed: %v", err)
	}
	if frame1.Offset != 0 {
		t.Fatalf("expected offset 0, got %d", frame1.Offset)
	}

	frame2, err := mux.WriteStreamData(s0, []byte("World!"), true)
	if err != nil {
		t.Fatalf("write frame2 failed: %v", err)
	}
	if frame2.Offset != 6 || !frame2.Fin {
		t.Fatalf("expected offset 6 and fin, got %d, %v", frame2.Offset, frame2.Fin)
	}

	receiver := NewQuicStreamMultiplexer(65536)
	// Receive out of order: frame2 first
	p2, err := receiver.ReceiveStreamFrame(frame2)
	if err != nil {
		t.Fatalf("receive frame2 failed: %v", err)
	}
	if len(p2) != 0 {
		t.Fatalf("expected empty assembled bytes before offset 0, got %d", len(p2))
	}

	// Now receive frame1
	p1, err := receiver.ReceiveStreamFrame(frame1)
	if err != nil {
		t.Fatalf("receive frame1 failed: %v", err)
	}
	if !bytes.Equal(p1, []byte("Hello World!")) {
		t.Fatalf("expected full assembled stream Hello World!, got %s", string(p1))
	}
	if !receiver.IsStreamClosed(s0) {
		t.Fatalf("expected stream closed")
	}
}
