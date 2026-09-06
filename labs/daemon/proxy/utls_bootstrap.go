package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// UTLSBootstrapTransport handles ALPN-based transport selection with zero-overhead connection reuse.
type UTLSBootstrapTransport struct {
	mu            sync.Mutex
	targetAddr    string
	bootstrapConn net.Conn
	alpn          string
	transport     http.RoundTripper
}

// NewUTLSBootstrapTransport creates a new UTLSBootstrapTransport instance.
func NewUTLSBootstrapTransport(targetAddr string) *UTLSBootstrapTransport {
	return &UTLSBootstrapTransport{
		targetAddr: targetAddr,
	}
}

// DialAndPeek performs the initial uTLS handshake, peeks at the ALPN negotiation,
// and configures the corresponding HTTP transport.
func (t *UTLSBootstrapTransport) DialAndPeek(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.transport != nil {
		return nil
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", t.targetAddr)
	if err != nil {
		return err
	}

	// Wrap with uTLS HelloChrome client hello
	uConfig := &utls.Config{
		InsecureSkipVerify: true, // Configurable per deployment environment
	}
	uConn := utls.UClient(rawConn, uConfig, utls.HelloChrome_Auto)

	err = uConn.Handshake()
	if err != nil {
		rawConn.Close()
		return err
	}

	state := uConn.ConnectionState()
	t.alpn = state.NegotiatedProtocol
	t.bootstrapConn = uConn

	if t.alpn == "h2" {
		// Negotiated HTTP/2: configure HTTP/2 transport
		h2Trans := &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		t.transport = h2Trans
	} else {
		// Fallback to HTTP/1.1
		h1Trans := http.DefaultTransport.(*http.Transport).Clone()
		h1Trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		t.transport = h1Trans
	}

	return nil
}

// RoundTrip implements http.RoundTripper by reusing the initial bootstrap connection
// for the first request, and executing subsequent requests normally over the configured transport.
func (t *UTLSBootstrapTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	conn := t.bootstrapConn
	t.bootstrapConn = nil // Reset so we only reuse it once
	trans := t.transport
	t.mu.Unlock()

	if conn != nil && trans != nil {
		// If it's HTTP/2, we can run ClientConn on the hijacked bootstrap connection
		if t.alpn == "h2" {
			if h2Trans, ok := trans.(*http2.Transport); ok {
				cc, err := h2Trans.NewClientConn(conn)
				if err == nil {
					return cc.RoundTrip(req)
				}
			}
		} else {
			// For HTTP/1.1, we can create a custom transport that uses this connection once
			oneOffTrans := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return conn, nil
				},
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			return oneOffTrans.RoundTrip(req)
		}
	}

	if trans != nil {
		return trans.RoundTrip(req)
	}

	return http.DefaultTransport.RoundTrip(req)
}
