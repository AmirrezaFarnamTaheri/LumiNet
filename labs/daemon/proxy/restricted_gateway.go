// Ported from: hawk-proxy-main
// Target path: server/internal/proxy/restricted_gateway.go

package proxy

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// RestrictedGateway enforces token-based authorization on a local loopback proxy listener.
type RestrictedGateway struct {
	ListenAddr string
	AuthToken  string
	listener   net.Listener
	wg         sync.WaitGroup
	quit       chan struct{}
}

// NewRestrictedGateway creates a new gateway instance.
func NewRestrictedGateway(listen, token string) *RestrictedGateway {
	return &RestrictedGateway{
		ListenAddr: listen,
		AuthToken:  token,
		quit:       make(chan struct{}),
	}
}

// Start starts listening and verifying incoming connections.
func (g *RestrictedGateway) Start() error {
	var err error
	g.listener, err = net.Listen("tcp", g.ListenAddr)
	if err != nil {
		return fmt.Errorf("restricted_gateway: listen: %w", err)
	}

	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for {
			conn, err := g.listener.Accept()
			if err != nil {
				select {
				case <-g.quit:
					return
				default:
					continue
				}
			}
			go g.handleConnection(conn)
		}
	}()

	return nil
}

func (g *RestrictedGateway) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	// Validate authorization header
	authHeader := req.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		authHeader = req.Header.Get("Authorization")
	}

	// Format: "Bearer <token>" or "Basic <base64(token)>"
	token := ""
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else if strings.HasPrefix(authHeader, "Basic ") {
		// Just treat Basic credentials as token checks for loopback simplification
		token = strings.TrimPrefix(authHeader, "Basic ")
	}

	if !g.verifyToken(token) {
		resp := "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Restricted Loopback\"\r\nContent-Length: 0\r\n\r\n"
		_, _ = conn.Write([]byte(resp))
		return
	}

	// Proceed with standard HTTP/HTTPS CONNECT routing
	if req.Method == "CONNECT" {
		target, err := net.Dial("tcp", req.URL.Host)
		if err != nil {
			resp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
			_, _ = conn.Write([]byte(resp))
			return
		}
		defer target.Close()

		_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			return
		}

		// Pipe bi-directionally
		var wg sync.WaitGroup
		wg.Add(2)
		pipeStream := func(a, b net.Conn) {
			defer wg.Done()
			_, _ = io.Copy(a, b)
		}
		go pipeStream(conn, target)
		go pipeStream(target, conn)
		wg.Wait()
	} else {
		// Passthrough HTTP
		target, err := net.Dial("tcp", req.URL.Host)
		if err != nil {
			resp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
			_, _ = conn.Write([]byte(resp))
			return
		}
		defer target.Close()

		_ = req.Write(target)
		var wg sync.WaitGroup
		wg.Add(2)
		pipeStream := func(a, b net.Conn) {
			defer wg.Done()
			_, _ = io.Copy(a, b)
		}
		go pipeStream(conn, target)
		go pipeStream(target, conn)
		wg.Wait()
	}
}

func (g *RestrictedGateway) verifyToken(token string) bool {
	// Constant-time compare to prevent timing side-channel attacks
	return subtle.ConstantTimeCompare([]byte(token), []byte(g.AuthToken)) == 1
}

// Stop shuts down the restricted gateway.
func (g *RestrictedGateway) Stop() {
	close(g.quit)
	if g.listener != nil {
		g.listener.Close()
	}
	g.wg.Wait()
}
