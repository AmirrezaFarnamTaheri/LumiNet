package relayclient

import (
	"bytes"
	"testing"
)

func TestPrependFailedWritePreservesPendingBytes(t *testing.T) {
	var buf bytes.Buffer
	_, _ = buf.WriteString("pending")
	prependFailedWrite(&buf, []byte("failed-"))
	if got := buf.String(); got != "failed-pending" {
		t.Fatalf("rollback buffer=%q, want %q", got, "failed-pending")
	}
}

func TestPrependFailedWriteDoesNotAliasPendingStorage(t *testing.T) {
	var buf bytes.Buffer
	_, _ = buf.WriteString("newer-data")
	prependFailedWrite(&buf, []byte("a-much-longer-failed-payload-"))
	if got := buf.String(); got != "a-much-longer-failed-payload-newer-data" {
		t.Fatalf("rollback buffer=%q", got)
	}
}
