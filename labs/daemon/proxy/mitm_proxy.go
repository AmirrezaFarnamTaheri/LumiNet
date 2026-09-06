// Ported from: mitm-proxy-main
// Target path: server/internal/proxy/mitm_proxy.go

package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// MitmProxy is an HTTP/HTTPS proxy server that decrypts SSL connections.
type MitmProxy struct {
	ListenAddr string
	decryptor  *MitmDecryptor
	listener   net.Listener
	wg         sync.WaitGroup
	quit       chan struct{}
}

// NewMitmProxy creates a new proxy instance.
func NewMitmProxy(listen string, dec *MitmDecryptor) *MitmProxy {
	return &MitmProxy{
		ListenAddr: listen,
		decryptor:  dec,
		quit:       make(chan struct{}),
	}
}

// Start starts listening for proxy requests.
func (p *MitmProxy) Start() error {
	var err error
	p.listener, err = net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return fmt.Errorf("mitm_proxy: listen: %w", err)
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, err := p.listener.Accept()
			if err != nil {
				select {
				case <-p.quit:
					return
				default:
					continue
				}
			}
			go p.handleConnection(conn)
		}
	}()

	return nil
}

func (p *MitmProxy) handleConnection(client net.Conn) {
	defer client.Close()

	reader := bufio.NewReader(client)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == "CONNECT" {
		p.handleHTTPS(client, req)
	} else {
		p.handleHTTP(client, req)
	}
}

func (p *MitmProxy) handleHTTP(client net.Conn, req *http.Request) {
	// Simple HTTP pass-through
	target, err := net.Dial("tcp", req.URL.Host)
	if err != nil {
		httpError(client, 502, "Bad Gateway")
		return
	}
	defer target.Close()

	// Forward request
	_ = req.Write(target)

	// Pipe bi-directionally
	pipe(client, target)
}

func (p *MitmProxy) handleHTTPS(client net.Conn, req *http.Request) {
	// Respond 200 Connection Established
	_, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		return
	}

	hostPort := req.URL.Host
	host := hostPort
	if strings.Contains(hostPort, ":") {
		h, _, _ := net.SplitHostPort(hostPort)
		host = h
	}

	// Fetch dynamic cert for host
	cert, err := p.decryptor.GetCertificate(host)
	if err != nil {
		return
	}

	// Upgrade client connection to TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsClient := tls.Server(client, tlsConfig)
	if err := tlsClient.Handshake(); err != nil {
		return
	}
	defer tlsClient.Close()

	// Connect upstream target
	target, err := tls.Dial("tcp", hostPort, &tls.Config{
		InsecureSkipVerify: true, // test/development bypass
	})
	if err != nil {
		return
	}
	defer target.Close()

	// Pipe decrypted streams bi-directionally
	pipe(tlsClient, target)
}

func httpError(conn net.Conn, code int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", code, msg, len(msg), msg)
	_, _ = conn.Write([]byte(resp))
}

func pipe(src, dst net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyChan := func(a, b net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(a, b)
	}
	go copyChan(src, dst)
	go copyChan(dst, src)
	wg.Wait()
}

// Stop shuts down the proxy server.
func (p *MitmProxy) Stop() {
	close(p.quit)
	if p.listener != nil {
		p.listener.Close()
	}
	p.wg.Wait()
}

// Ported from: go-mitmproxy-main / mitm-proxy-main
