package proxy

import (
	"context"
	"errors"
	"testing"
)

func TestGDriveMailboxRejectsMissingCredentials(t *testing.T) {
	cases := []struct{ folder, session, token string }{
		{"", "session", "token"},
		{"folder", "", "token"},
		{"folder", "session", ""},
	}
	for _, tc := range cases {
		if _, err := NewGDriveMailbox(tc.folder, tc.session, tc.token); err == nil {
			t.Fatalf("NewGDriveMailbox(%q,%q,<token=%t>) accepted incomplete credentials", tc.folder, tc.session, tc.token != "")
		}
	}
}

func TestGDriveVirtualConnectionUsesCallerContext(t *testing.T) {
	mailbox, err := NewGDriveMailbox("folder", "session", "token")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn := mailbox.VirtualConnection(ctx)
	_, err = conn.Write([]byte("payload"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Write error = %v, want context.Canceled", err)
	}
}

func TestZephyrEnvelopeEncodingDecoding(t *testing.T) {
	original := &ZephyrEnvelope{SessionID: "test-session-xyz", Seq: 42, TargetAddr: "google.com:443", Payload: []byte("hello world payload binary data"), Close: true}
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeZephyrEnvelope(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.SessionID != original.SessionID || decoded.Seq != original.Seq || decoded.TargetAddr != original.TargetAddr || decoded.Close != original.Close || string(decoded.Payload) != string(original.Payload) {
		t.Fatalf("round trip mismatch: got %+v want %+v", decoded, original)
	}
}
