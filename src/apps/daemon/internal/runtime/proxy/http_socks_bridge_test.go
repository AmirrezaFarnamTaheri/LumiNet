package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/maybeknott/luminet/internal/foundation/boundedio"
	"time"
)

type mockSocksObservation struct {
	host string
	port int
	data string
}

func startMockBridgeSOCKS(t *testing.T, afterConnect func(net.Conn, chan<- mockSocksObservation)) (string, <-chan mockSocksObservation, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan mockSocksObservation, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(c, greeting); err != nil {
					return
				}
				if string(greeting) != string([]byte{0x05, 0x01, 0x00}) {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00})
				header := make([]byte, 4)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}
				if header[0] != 0x05 || header[1] != 0x01 {
					return
				}
				var host string
				switch header[3] {
				case 0x01:
					buf := make([]byte, 4)
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					host = net.IP(buf).String()
				case 0x03:
					var n [1]byte
					if _, err := io.ReadFull(c, n[:]); err != nil {
						return
					}
					buf := make([]byte, int(n[0]))
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					host = string(buf)
				case 0x04:
					buf := make([]byte, 16)
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					host = net.IP(buf).String()
				default:
					return
				}
				var pb [2]byte
				if _, err := io.ReadFull(c, pb[:]); err != nil {
					return
				}
				port := int(pb[0])<<8 | int(pb[1])
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
				observed <- mockSocksObservation{host: host, port: port}
				if afterConnect != nil {
					afterConnect(c, observed)
				}
			}(conn)
		}
	}()
	return listener.Addr().String(), observed, func() { _ = listener.Close() }
}

func TestHTTPSOCKSBridgeCONNECTUsesDomainAndPreservesBufferedPayload(t *testing.T) {
	socksAddr, observed, stopSocks := startMockBridgeSOCKS(t, func(c net.Conn, ch chan<- mockSocksObservation) {
		buf := make([]byte, 4)
		_, _ = io.ReadFull(c, buf)
		ch <- mockSocksObservation{data: string(buf)}
		_, _ = c.Write([]byte("PONG"))
	})
	defer stopSocks()
	bridge, err := startHTTPSOCKSBridge(socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	host, _, err := net.SplitHostPort(bridge.Addr())
	if err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatalf("bridge not loopback: %q %v", bridge.Addr(), err)
	}
	client, err := net.Dial("tcp", bridge.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = io.WriteString(client, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\nPING")
	reader := bufio.NewReader(client)
	status, err := boundedio.ReadLine(reader, maxHTTPProxyHeaderBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("status=%q", status)
	}
	for {
		line, err := boundedio.ReadLine(reader, maxHTTPProxyHeaderBytes)
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "PONG" {
		t.Fatalf("reply=%q", buf)
	}
	first := <-observed
	if first.host != "example.test" || first.port != 443 {
		t.Fatalf("SOCKS target=%+v", first)
	}
	second := <-observed
	if second.data != "PING" {
		t.Fatalf("buffered payload=%q", second.data)
	}
}

func TestHTTPSOCKSBridgeRewritesHTTPAndStripsProxyCredentials(t *testing.T) {
	socksAddr, observed, stopSocks := startMockBridgeSOCKS(t, func(c net.Conn, ch chan<- mockSocksObservation) {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		reader := bufio.NewReader(c)
		line, _ := boundedio.ReadLine(reader, maxHTTPProxyHeaderBytes)
		headers := ""
		for {
			h, err := boundedio.ReadLine(reader, maxHTTPProxyHeaderBytes)
			if err != nil {
				break
			}
			headers += h
			if h == "\r\n" {
				break
			}
		}
		ch <- mockSocksObservation{data: line + headers}
		_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	})
	defer stopSocks()
	bridge, err := startHTTPSOCKSBridge(socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	client, err := net.Dial("tcp", bridge.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = io.WriteString(client, "GET http://example.test/a?b=1 HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic secret\r\nProxy-Connection: keep-alive\r\n\r\n")
	reader := bufio.NewReader(client)
	status, err := boundedio.ReadLine(reader, maxHTTPProxyHeaderBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "204") {
		t.Fatalf("status=%q", status)
	}
	first := <-observed
	if first.host != "example.test" || first.port != 80 {
		t.Fatalf("target=%+v", first)
	}
	second := <-observed
	if !strings.HasPrefix(second.data, "GET /a?b=1 HTTP/1.1\r\n") {
		t.Fatalf("forwarded request=%q", second.data)
	}
	if strings.Contains(strings.ToLower(second.data), "proxy-authorization") || strings.Contains(strings.ToLower(second.data), "proxy-connection") {
		t.Fatalf("proxy credentials/hop header leaked: %q", second.data)
	}
}

func TestHTTPSOCKSBridgeRejectsOversizedHeaderBeforeUpstream(t *testing.T) {
	socksAddr, _, stopSocks := startMockBridgeSOCKS(t, nil)
	defer stopSocks()
	bridge, err := startHTTPSOCKSBridge(socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	client, err := net.Dial("tcp", bridge.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	payload := "GET http://example.test/ HTTP/1.1\r\nX-Fill: " + strings.Repeat("x", maxHTTPProxyHeaderBytes) + "\r\n"
	_, _ = io.WriteString(client, payload)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	line, err := boundedio.ReadLine(bufio.NewReader(client), maxHTTPProxyHeaderBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "431") {
		t.Fatalf("oversized header response=%q", line)
	}
}

func TestHTTPSOCKSBridgeCloseIsPrompt(t *testing.T) {
	socksAddr, _, stopSocks := startMockBridgeSOCKS(t, func(c net.Conn, _ chan<- mockSocksObservation) {})
	defer stopSocks()
	bridge, err := startHTTPSOCKSBridge(socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.Dial("tcp", bridge.Addr())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(client, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n")
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = client.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("client remained connected after bridge close")
	}
	_ = client.Close()
}
