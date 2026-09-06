// SPDX-License-Identifier: MIT

package transport

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDataChannelFrameEncoding(t *testing.T) {
	payload := []byte("hello webrtc datachannel payload bytes 12345")
	frame := &DataChannelFrame{
		PPID:    WebRTCPPIDBinary,
		Payload: payload,
	}

	encoded := frame.Encode()
	if len(encoded) != 4+len(payload) {
		t.Fatalf("unexpected encoded length: got %d, want %d", len(encoded), 4+len(payload))
	}

	decoded, err := DecodeDataChannelFrame(encoded)
	if err != nil {
		t.Fatalf("failed decoding frame: %v", err)
	}

	if decoded.PPID != WebRTCPPIDBinary {
		t.Errorf("expected PPID %d, got %d", WebRTCPPIDBinary, decoded.PPID)
	}

	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("payload mismatch: got %v, want %v", decoded.Payload, payload)
	}

	// Test short frame error
	if _, err := DecodeDataChannelFrame([]byte{1, 2}); err == nil {
		t.Error("expected error decoding frame shorter than 4 bytes")
	}
}

func TestWebRTCDataChannelConnStreaming(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientWrapped := WrapDataChannelConn(clientConn)
	serverWrapped := WrapDataChannelConn(serverConn)

	msg := []byte("covert packet framed in webrtc datachannel")

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := serverWrapped.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(buf[:n], msg) {
			errCh <- fmt.Errorf("server read mismatch: got %s, want %s", string(buf[:n]), string(msg))
			return
		}
		// Echo back
		_, err = serverWrapped.Write(buf[:n])
		errCh <- err
	}()

	// Client write
	n, err := clientWrapped.Write(msg)
	if err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	if n != len(msg) {
		t.Fatalf("client wrote %d bytes, expected %d", n, len(msg))
	}

	// Client read echo
	readBuf := make([]byte, 1024)
	readN, err := clientWrapped.Read(readBuf)
	if err != nil {
		t.Fatalf("client read echo failed: %v", err)
	}

	if !bytes.Equal(readBuf[:readN], msg) {
		t.Fatalf("client received echo mismatch: got %s, want %s", string(readBuf[:readN]), string(msg))
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server routine failed: %v", err)
	}
}

func TestICEProxyDialerConnect(t *testing.T) {
	// 1. Start a target echo server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target listener: %v", err)
	}
	defer targetListener.Close()

	targetAddr := targetListener.Addr().String()

	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Start a mock HTTP CONNECT proxy
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy listener: %v", err)
	}
	defer proxyListener.Close()

	expectedUser := "testuser"
	expectedPass := "testsecret123"

	go func() {
		for {
			clientConn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}

				if req.Method != http.MethodConnect {
					c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
					return
				}

				// Check auth
				auth := req.Header.Get("Proxy-Authorization")
				if !strings.HasPrefix(auth, "Basic ") {
					c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
					return
				}

				// Connect to target
				targetConn, err := net.Dial("tcp", req.Host)
				if err != nil {
					c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer targetConn.Close()

				c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

				go io.Copy(c, targetConn)
				io.Copy(targetConn, c)
			}(clientConn)
		}
	}()

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyListener.Addr().String()))
	if err != nil {
		t.Fatalf("failed parsing proxy URL: %v", err)
	}

	dialer, err := NewICEProxyDialer(ICEProxyConfig{
		ProxyURL: proxyURL,
		Username: expectedUser,
		Password: expectedPass,
		Timeout:  3 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed creating dialer: %v", err)
	}

	conn, err := dialer.DialContext(context.Background(), "tcp", targetAddr)
	if err != nil {
		t.Fatalf("dialer failed to connect through proxy: %v", err)
	}
	defer conn.Close()

	// Verify data transit
	testMsg := []byte("hello through ice proxy dialer!")
	if _, err := conn.Write(testMsg); err != nil {
		t.Fatalf("write through proxy failed: %v", err)
	}

	recvBuf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(conn, recvBuf); err != nil {
		t.Fatalf("read echo through proxy failed: %v", err)
	}

	if !bytes.Equal(recvBuf, testMsg) {
		t.Fatalf("echo mismatch: got %s, want %s", string(recvBuf), string(testMsg))
	}
}

func TestICEProxyDialerAuthenticationError(t *testing.T) {
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy listener: %v", err)
	}
	defer proxyListener.Close()

	go func() {
		c, err := proxyListener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		http.ReadRequest(bufio.NewReader(c))
		c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
	}()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://%s", proxyListener.Addr().String()))
	dialer, _ := NewICEProxyDialer(ICEProxyConfig{
		ProxyURL: proxyURL,
		Timeout:  2 * time.Second,
	})

	_, err = dialer.DialContext(context.Background(), "tcp", "1.1.1.1:80")
	if err == nil {
		t.Fatal("expected error on 407 status code, got nil")
	}
	if !strings.Contains(err.Error(), "407") {
		t.Fatalf("expected 407 in error message, got: %v", err)
	}
}

func TestICEProxyDialerInvalidScheme(t *testing.T) {
	proxyURL, _ := url.Parse("socks5://127.0.0.1:1080")
	_, err := NewICEProxyDialer(ICEProxyConfig{
		ProxyURL: proxyURL,
	})
	if err == nil {
		t.Fatal("expected error for non-http/https proxy scheme in ICEProxyDialer")
	}
}
