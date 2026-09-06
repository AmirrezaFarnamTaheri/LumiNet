package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// HTTPProxyServer implements a cross-platform HTTP proxy listener with header parsing.
type HTTPProxyServer struct {
	addr     string
	listener net.Listener
	mu       sync.Mutex
	running  bool
}

func NewHTTPProxyServer(addr string) *HTTPProxyServer {
	return &HTTPProxyServer{addr: addr}
}

func (s *HTTPProxyServer) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("http proxy server already running")
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.listener = ln
	s.running = true
	s.mu.Unlock()

	go s.acceptLoop(ctx)
	return nil
}

func (s *HTTPProxyServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.running = false
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *HTTPProxyServer) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConnection(ctx, conn)
	}
}

func (s *HTTPProxyServer) handleConnection(ctx context.Context, client net.Conn) {
	defer client.Close()

	reader := bufio.NewReader(client)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	if !strings.Contains(host, ":") {
		if req.Method == "CONNECT" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	target, err := net.Dial("tcp", host)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer target.Close()

	if req.Method == "CONNECT" {
		_, err = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			return
		}
	} else {
		err = req.Write(target)
		if err != nil {
			return
		}
	}

	go func() {
		_, _ = io.Copy(target, reader)
	}()
	_, _ = io.Copy(client, target)
}
