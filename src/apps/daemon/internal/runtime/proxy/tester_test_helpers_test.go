package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// startMockSocks5 starts a minimal SOCKS5 server for testing.
// It accepts connections and pipes them directly to the requested destination address.
func startMockSocks5(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startMockSocks5: failed to listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockSocks5Conn(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func handleMockSocks5Conn(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 256)
	// Read greeting
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}
	// Send no-auth response
	conn.Write([]byte{0x05, 0x00})

	// Read connect request header (4 bytes)
	header := make([]byte, 4)
	_, err = io.ReadFull(conn, header)
	if err != nil {
		return
	}

	// Check connection type
	if header[1] != 0x01 { // Only support CONNECT
		return
	}

	var destAddr string
	switch header[3] {
	case 0x01: // IPv4 (4 bytes)
		ip := make([]byte, 4)
		_, err = io.ReadFull(conn, ip)
		if err != nil {
			return
		}
		portBuf := make([]byte, 2)
		_, err = io.ReadFull(conn, portBuf)
		if err != nil {
			return
		}
		port := binary.BigEndian.Uint16(portBuf)
		destAddr = fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], port)
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		_, err = io.ReadFull(conn, lenBuf)
		if err != nil {
			return
		}
		length := int(lenBuf[0])
		domainBuf := make([]byte, length)
		_, err = io.ReadFull(conn, domainBuf)
		if err != nil {
			return
		}
		portBuf := make([]byte, 2)
		_, err = io.ReadFull(conn, portBuf)
		if err != nil {
			return
		}
		port := binary.BigEndian.Uint16(portBuf)
		destAddr = fmt.Sprintf("%s:%d", string(domainBuf), port)
	default:
		return // Unsupported address type
	}

	// Dial target address
	target, err := net.DialTimeout("tcp", destAddr, 5*time.Second)
	if err != nil {
		// Send failure reply
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer target.Close()

	// Send success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Pipe traffic
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, conn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(conn, target)
		errChan <- err
	}()
	<-errChan
}
