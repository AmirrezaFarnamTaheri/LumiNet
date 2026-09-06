// Package proxy provides the DualProxyServer — a concurrent SOCKS5 and HTTP
// local proxy listener used by LumiNet to expose both proxy protocols on
// configurable loopback ports from a single server instance.
//
// Ported from: GNet-master (android proxy server / socket loop multiplexing)
// LumiNet target: server/internal/proxy/dual_proxy_server.go
package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DualProxyServer runs concurrent SOCKS5 and HTTP local proxies on configurable
// loopback ports. It is the LumiNet equivalent of GNet-master's server socket
// loop multiplexing, adapted for the Go daemon layer.
type DualProxyServer struct {
	socksListener net.Listener
	httpListener  net.Listener
	wg            sync.WaitGroup
	running       bool
	mu            sync.Mutex
}

// NewDualProxyServer creates a DualProxyServer instance.
func NewDualProxyServer() *DualProxyServer {
	return &DualProxyServer{}
}

// Start launches both SOCKS5 (on socksPort) and HTTP (on httpPort) proxy listeners
// concurrently. Both bind to 127.0.0.1. Returns an error if either port fails to bind.
func (s *DualProxyServer) Start(socksPort, httpPort int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("dual proxy server is already running")
	}

	var err error
	s.socksListener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort))
	if err != nil {
		return fmt.Errorf("failed to bind socks5 port %d: %w", socksPort, err)
	}

	s.httpListener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", httpPort))
	if err != nil {
		s.socksListener.Close()
		return fmt.Errorf("failed to bind http port %d: %w", httpPort, err)
	}

	s.running = true
	s.wg.Add(2)

	go s.listenSocks5()
	go s.listenHTTP()

	return nil
}

// Stop gracefully stops both proxy servers and waits for active goroutines to exit.
func (s *DualProxyServer) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	if s.socksListener != nil {
		s.socksListener.Close()
	}
	if s.httpListener != nil {
		s.httpListener.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()
}

func (s *DualProxyServer) listenSocks5() {
	defer s.wg.Done()

	for {
		conn, err := s.socksListener.Accept()
		if err != nil {
			return
		}
		go s.handleSocks5(conn)
	}
}

func (s *DualProxyServer) listenHTTP() {
	defer s.wg.Done()

	for {
		conn, err := s.httpListener.Accept()
		if err != nil {
			return
		}
		go s.handleHTTP(conn)
	}
}

// handleSocks5 handles a single SOCKS5 client connection per RFC 1928.
// Supports IPv4 (0x01), domain name (0x03), and IPv6 (0x04) address types.
// Only the CONNECT command (0x01) is accepted; no authentication required.
func (s *DualProxyServer) handleSocks5(conn net.Conn) {
	defer conn.Close()

	// 1. Greeting: read version + number of methods
	buf := make([]byte, 257)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}

	if buf[0] != 0x05 { // Must be SOCKS5
		return
	}

	numMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:numMethods]); err != nil {
		return
	}

	// Respond: NO AUTHENTICATION REQUIRED (method 0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request: VER(1) CMD(1) RSV(1) ATYP(1) ...
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}

	if header[0] != 0x05 || header[1] != 0x01 { // Version 5, CONNECT only
		return
	}

	var host string
	switch header[3] { // Address type
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	// Dial target
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		// REP = 0x05 (Connection refused), BND.ADDR = 0.0.0.0:0
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()

	// REP = 0x00 (succeeded)
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	s.relayBidirectional(conn, target)
}

// handleHTTP handles a single HTTP/CONNECT proxy client connection.
// Supports both CONNECT (HTTPS tunneling) and plain HTTP forwarding.
func (s *DualProxyServer) handleHTTP(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	reqLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	reqLine = strings.TrimSpace(reqLine)
	parts := strings.Split(reqLine, " ")
	if len(parts) < 3 {
		return
	}

	method := parts[0]
	urlStr := parts[1]

	if method == "CONNECT" {
		s.handleHTTPConnect(conn, urlStr)
		return
	}

	// HTTP forward proxy: extract host from URL or Host header
	var host string
	var path string
	if strings.HasPrefix(urlStr, "http://") {
		trimmed := strings.TrimPrefix(urlStr, "http://")
		slashIdx := strings.Index(trimmed, "/")
		if slashIdx == -1 {
			host = trimmed
			path = "/"
		} else {
			host = trimmed[:slashIdx]
			path = trimmed[slashIdx:]
		}
	} else {
		path = urlStr
		host = s.getHostHeader(reader)
	}

	if host == "" {
		s.sendHTTPError(conn, 400, "Bad Request")
		return
	}

	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	target, err := net.Dial("tcp", host)
	if err != nil {
		s.sendHTTPError(conn, 500, "Internal Server Error")
		return
	}
	defer target.Close()

	fmt.Fprintf(target, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(target, "Host: %s\r\n", host)
	fmt.Fprintf(target, "Connection: close\r\n")

	// Forward client headers except Host/Connection (already rewritten above)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		lineLower := strings.ToLower(line)
		if !strings.HasPrefix(lineLower, "host:") && !strings.HasPrefix(lineLower, "connection:") {
			_, _ = target.Write([]byte(line))
		}
	}
	_, _ = target.Write([]byte("\r\n"))

	s.relayBidirectional(conn, target)
}

// handleHTTPConnect handles HTTP CONNECT tunneling (for HTTPS).
func (s *DualProxyServer) handleHTTPConnect(conn net.Conn, targetAddr string) {
	if !strings.Contains(targetAddr, ":") {
		targetAddr = targetAddr + ":443"
	}

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		s.sendHTTPError(conn, 500, "Internal Server Error")
		return
	}
	defer target.Close()

	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	s.relayBidirectional(conn, target)
}

// getHostHeader reads HTTP headers from reader and returns the value of the Host header.
func (s *DualProxyServer) getHostHeader(reader *bufio.Reader) string {
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}

// sendHTTPError writes a minimal HTTP error response.
func (s *DualProxyServer) sendHTTPError(conn net.Conn, code int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s", code, msg, msg)
	_, _ = conn.Write([]byte(resp))
}

// relayBidirectional copies data between c1 and c2 in both directions concurrently.
// Sets a read deadline on the other connection when one direction finishes, ensuring
// clean shutdown without goroutine leaks.
func (s *DualProxyServer) relayBidirectional(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(c1, c2)
		_ = c1.SetReadDeadline(time.Now())
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(c2, c1)
		_ = c2.SetReadDeadline(time.Now())
	}()

	wg.Wait()
}
