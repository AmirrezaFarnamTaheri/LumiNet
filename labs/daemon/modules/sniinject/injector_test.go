package sniinject

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestSplitClientHello(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte("TLS_CLIENT_HELLO_SNI_EXAMPLE_PAYLOAD")

	errCh := make(chan error, 1)
	readBuf := new(bytes.Buffer)

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := server.Read(buf)
			if n > 0 {
				readBuf.Write(buf[:n])
			}
			if readBuf.Len() >= len(payload) || err != nil {
				break
			}
		}
		errCh <- nil
	}()

	cfg := SplitConfig{
		SplitOffset: 10,
		Delay:       10 * time.Millisecond,
	}

	if err := SplitClientHello(client, payload, cfg); err != nil {
		t.Fatalf("SplitClientHello failed: %v", err)
	}

	<-errCh

	if !bytes.Equal(readBuf.Bytes(), payload) {
		t.Errorf("reassembled payload mismatch. Expected %s, got %s", payload, readBuf.Bytes())
	}
}
