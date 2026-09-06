package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

type mockTunDevice struct {
	readPipe  *io.PipeReader
	writePipe *io.PipeWriter
}

func newMockTunDevice() *mockTunDevice {
	r, w := io.Pipe()
	return &mockTunDevice{
		readPipe:  r,
		writePipe: w,
	}
}

func (m *mockTunDevice) Read(p []byte) (n int, err error) {
	return m.readPipe.Read(p)
}

func (m *mockTunDevice) Write(p []byte) (n int, err error) {
	return m.writePipe.Write(p)
}

func (m *mockTunDevice) Close() error {
	m.readPipe.Close()
	m.writePipe.Close()
	return nil
}

func TestGvisorNetstack_AcceptTCP(t *testing.T) {
	tun := newMockTunDevice()
	stack := NewGvisorStack(tun)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := stack.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Construct and write a mock IPv4 TCP packet into the tun device
	packet := make([]byte, 40)
	packet[0] = 0x45                                             // Version 4, IHL = 5
	packet[9] = 6                                                // TCP
	packet[12], packet[13], packet[14], packet[15] = 10, 0, 0, 2 // Src IP
	packet[16], packet[17], packet[18], packet[19] = 10, 0, 0, 1 // Dst IP

	binary.BigEndian.PutUint16(packet[20:22], 12345) // Src Port
	binary.BigEndian.PutUint16(packet[22:24], 80)    // Dst Port

	go func() {
		tun.writePipe.Write(packet)
	}()

	acceptChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)

	go func() {
		conn, err := stack.AcceptTCP()
		if err != nil {
			errChan <- err
		} else {
			acceptChan <- conn
		}
	}()

	select {
	case conn := <-acceptChan:
		if conn.LocalAddr().String() != "10.0.0.2:12345" {
			t.Errorf("expected local address 10.0.0.2:12345, got %s", conn.LocalAddr().String())
		}
		if conn.RemoteAddr().String() != "10.0.0.1:80" {
			t.Errorf("expected remote address 10.0.0.1:80, got %s", conn.RemoteAddr().String())
		}
		conn.Close()
	case err := <-errChan:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for AcceptTCP")
	}

	stack.Close()
}

func TestLwipNetstack_AcceptUDP(t *testing.T) {
	tun := newMockTunDevice()
	stack := NewLwipStack(tun)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := stack.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Construct and write a mock IPv4 UDP packet into the tun device
	packet := make([]byte, 40)
	packet[0] = 0x45                                             // Version 4, IHL = 5
	packet[9] = 17                                               // UDP
	packet[12], packet[13], packet[14], packet[15] = 10, 0, 0, 3 // Src IP
	packet[16], packet[17], packet[18], packet[19] = 10, 0, 0, 1 // Dst IP

	binary.BigEndian.PutUint16(packet[20:22], 23456) // Src Port
	binary.BigEndian.PutUint16(packet[22:24], 53)    // Dst Port

	go func() {
		tun.writePipe.Write(packet)
	}()

	acceptChan := make(chan net.PacketConn, 1)
	errChan := make(chan error, 1)

	go func() {
		conn, err := stack.AcceptUDP()
		if err != nil {
			errChan <- err
		} else {
			acceptChan <- conn
		}
	}()

	select {
	case conn := <-acceptChan:
		if conn.LocalAddr().String() != "10.0.0.3:23456" {
			t.Errorf("expected local address 10.0.0.3:23456, got %s", conn.LocalAddr().String())
		}
		conn.Close()
	case err := <-errChan:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for AcceptUDP")
	}

	stack.Close()
}
