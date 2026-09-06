package proxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestNaivePaddingConn_ReadWrite(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	done := make(chan struct{})
	payload := []byte("hello-naive-world")

	go func() {
		defer close(done)
		rawConn, err := l.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()

		// Server side padding conn
		serverConn := NewNaivePaddingConn(rawConn)
		buf := make([]byte, 100)
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Errorf("server read error: %v", err)
			return
		}

		if !bytes.Equal(buf[:n], payload) {
			t.Errorf("expected read payload %q, got %q", payload, buf[:n])
			return
		}

		// Echo back
		_, _ = serverConn.Write(payload)
	}()

	rawClient, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer rawClient.Close()

	clientConn := NewNaivePaddingConn(rawClient)

	// Write payload (first write, padded)
	_, err = clientConn.Write(payload)
	if err != nil {
		t.Fatalf("failed to write padded: %v", err)
	}

	// Read echo
	buf := make([]byte, 100)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("expected echo payload %q, got %q", payload, buf[:n])
	}

	// Test End Stream Padding
	err = clientConn.WriteEndStream()
	if err != nil {
		t.Errorf("failed to write end stream: %v", err)
	}

	<-done
}

func TestDNSPacketConn_WindowScaling(t *testing.T) {
	conn := NewDNSPacketConn()
	conn.minDelay = 50 * time.Millisecond
	conn.maxDelay = 200 * time.Millisecond
	conn.currentDelay = 50 * time.Millisecond

	var pollCount int64
	sendPoll := func() error {
		atomic.AddInt64(&pollCount, 1)
		return errors.New("idle/fail") // Forces doubling
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn.StartLoop(ctx, sendPoll)

	// Wait for a few poll cycles
	time.Sleep(300 * time.Millisecond)

	// Check if delay scaled up
	delay := conn.getDelay()
	if delay < conn.minDelay {
		t.Errorf("delay did not scale or initialize properly: %v", delay)
	}

	// Notify traffic: should reset delay back to minDelay
	conn.NotifyTraffic()
	time.Sleep(20 * time.Millisecond)

	newDelay := conn.getDelay()
	if newDelay > conn.minDelay*2 {
		t.Errorf("delay was not reset by traffic: %v", newDelay)
	}

	conn.Stop()
}
