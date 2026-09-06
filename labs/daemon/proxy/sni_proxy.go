package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SNIProxyServer implements a pure Go userspace SNI proxy.
type SNIProxyServer struct {
	addr     string
	listener net.Listener
	mu       sync.Mutex
	running  bool
}

func NewSNIProxyServer(addr string) *SNIProxyServer {
	return &SNIProxyServer{addr: addr}
}

func (s *SNIProxyServer) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("sni proxy already running")
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

func (s *SNIProxyServer) Stop() {
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

func (s *SNIProxyServer) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConnection(ctx, conn)
	}
}

func (s *SNIProxyServer) handleConnection(ctx context.Context, client net.Conn) {
	defer client.Close()

	buf := make([]byte, 2048)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.ReadAtLeast(client, buf, 5)
	if err != nil {
		return
	}
	_ = client.SetReadDeadline(time.Time{})

	sni, err := ParseSNIFromClientHello(buf[:n])
	if err != nil {
		return
	}

	target, err := net.DialTimeout("tcp", net.JoinHostPort(sni, "443"), 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	_, err = target.Write(buf[:n])
	if err != nil {
		return
	}

	go func() {
		_, _ = io.Copy(target, client)
	}()
	_, _ = io.Copy(client, target)
}

func ParseSNIFromClientHello(data []byte) (string, error) {
	if len(data) < 5 {
		return "", errors.New("tls client hello too short")
	}

	if data[0] != 0x16 {
		return "", errors.New("not a tls handshake")
	}

	if len(data) < 43 {
		return "", errors.New("tls client hello header too short")
	}

	if data[5] != 1 {
		return "", errors.New("not a client hello handshake")
	}

	sessionIDLen := int(data[38])
	idx := 39 + sessionIDLen

	if idx+2 > len(data) {
		return "", errors.New("tls cipher suites length invalid")
	}
	cipherSuitesLen := int(data[idx])<<8 | int(data[idx+1])
	idx += 2 + cipherSuitesLen

	if idx+1 > len(data) {
		return "", errors.New("tls compression methods invalid")
	}
	compLen := int(data[idx])
	idx += 1 + compLen

	if idx+2 > len(data) {
		return "", errors.New("tls extensions invalid")
	}
	extensionsLen := int(data[idx])<<8 | int(data[idx+1])
	idx += 2
	endIdx := idx + extensionsLen

	if endIdx > len(data) {
		endIdx = len(data)
	}

	for idx+4 <= endIdx {
		extType := int(data[idx])<<8 | int(data[idx+1])
		extLen := int(data[idx+2])<<8 | int(data[idx+3])
		idx += 4

		if extType == 0 {
			if idx+extLen > len(data) {
				return "", errors.New("sni extension length invalid")
			}
			sniBytes := data[idx : idx+extLen]
			if len(sniBytes) < 5 {
				return "", errors.New("sni extension too short")
			}
			if sniBytes[2] != 0 {
				return "", errors.New("sni type not host name")
			}
			nameLen := int(sniBytes[3])<<8 | int(sniBytes[4])
			if 5+nameLen > len(sniBytes) {
				return "", errors.New("sni name length invalid")
			}
			return string(sniBytes[5 : 5+nameLen]), nil
		}
		idx += extLen
	}

	return "", errors.New("sni extension not found")
}
