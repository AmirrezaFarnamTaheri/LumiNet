package transport

import (
	"bytes"
	"testing"
)

func TestTcpChunkSplitter(t *testing.T) {
	splitter := NewTcpChunkSplitter()
	data := []byte("GET /index.html HTTP/1.1")
	chunks := splitter.SplitBytes(data, 5)

	if len(chunks) != 5 {
		t.Fatalf("expected 5 chunks, got %d", len(chunks))
	}
	if !bytes.Equal(chunks[0], []byte("GET /")) {
		t.Fatalf("expected 'GET /', got '%s'", string(chunks[0]))
	}

	mutated := splitter.MutateHeaderCase("Host: example.com")
	if mutated != "hOsT: example.com" {
		t.Fatalf("expected 'hOsT: example.com', got '%s'", mutated)
	}
}
