// Package tunnel provides NAT traversal tunneling with HMAC-SHA256 authentication.
// Ported from bore (Rust TCP tunnel) with enhancements.
package tunnel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	ControlPort     = 7835
	MaxFrameLength  = 256
	NetworkTimeout  = 3 * time.Second
	HeartbeatInterval = 500 * time.Millisecond
	StaleTimeout    = 10 * time.Second
)

// ClientMessage represents messages from client to server.
type ClientMessage struct {
	Type string `json:"t"`
	Port uint16 `json:"p,omitempty"`
	UUID string `json:"u,omitempty"`
	Auth string `json:"a,omitempty"`
}

// ServerMessage represents messages from server to client.
type ServerMessage struct {
	Type string `json:"t"`
	Port uint16 `json:"p,omitempty"`
	UUID string `json:"u,omitempty"`
	Error string `json:"e,omitempty"`
}

// Authenticator implements HMAC-SHA256 challenge-response authentication.
// Ported from bore's auth.rs.
type Authenticator struct {
	key []byte
}

// NewAuthenticator creates a new HMAC authenticator from a secret.
func NewAuthenticator(secret string) *Authenticator {
	hash := sha256.Sum256([]byte(secret))
	return &Authenticator{key: hash[:]}
}

// Answer computes the HMAC-SHA256 response for a challenge UUID.
func (a *Authenticator) Answer(challenge string) string {
	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte(challenge))
	return hex.EncodeToString(mac.Sum(nil))
}

// Validate verifies an HMAC response against a challenge.
func (a *Authenticator) Validate(challenge, response string) bool {
	expected := a.Answer(challenge)
	return hmac.Equal([]byte(expected), []byte(response))
}

// TunnelServer manages tunnel connections.
type TunnelServer struct {
	portRange  [2]uint16
	auth       *Authenticator
	conns      sync.Map // uuid -> net.Conn
	bindAddr   string
}

// NewTunnelServer creates a new tunnel server.
func NewTunnelServer(minPort, maxPort uint16, secret, bindAddr string) *TunnelServer {
	s := &TunnelServer{
		portRange: [2]uint16{minPort, maxPort},
		bindAddr:  bindAddr,
	}
	if secret != "" {
		s.auth = NewAuthenticator(secret)
	}
	return s
}

// HandleConnection handles a single tunnel control connection.
func (s *TunnelServer) HandleConnection(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(NetworkTimeout))

	// Auth handshake if configured
	if s.auth != nil {
		challenge := uuid.New().String()
		if err := sendJSON(conn, ServerMessage{Type: "challenge", UUID: challenge}); err != nil {
			return err
		}

		var msg ClientMessage
		if err := recvJSON(conn, &msg); err != nil {
			return err
		}
		if msg.Type != "authenticate" || !s.auth.Validate(challenge, msg.Auth) {
			return sendJSON(conn, ServerMessage{Type: "error", Error: "authentication failed"})
		}
	}

	// Wait for Hello
	var hello ClientMessage
	if err := recvJSON(conn, &hello); err != nil {
		return err
	}
	if hello.Type != "hello" {
		return fmt.Errorf("expected hello, got %s", hello.Type)
	}

	// Bind public listener
	listener, port, err := s.createListener(hello.Port)
	if err != nil {
		return sendJSON(conn, ServerMessage{Type: "error", Error: err.Error()})
	}
	defer listener.Close()

	if err := sendJSON(conn, ServerMessage{Type: "hello", Port: port}); err != nil {
		return err
	}

	// Accept incoming connections and notify client
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if dl, ok := listener.(interface{ SetDeadline(time.Time) error }); ok {
			_ = dl.SetDeadline(time.Now().Add(HeartbeatInterval))
		}
		incoming, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Send heartbeat
				if err := sendJSON(conn, ServerMessage{Type: "heartbeat"}); err != nil {
					return err
				}
				continue
			}
			return err
		}

		connUUID := uuid.New().String()
		s.conns.Store(connUUID, incoming)

		// Clean stale connections after timeout
		go func(id string) {
			time.Sleep(StaleTimeout)
			if c, ok := s.conns.LoadAndDelete(id); ok {
				c.(net.Conn).Close()
			}
		}(connUUID)

		if err := sendJSON(conn, ServerMessage{Type: "connection", UUID: connUUID}); err != nil {
			incoming.Close()
			return err
		}
	}
}

// AcceptTunnel accepts a tunnel data connection from a client.
func (s *TunnelServer) AcceptTunnel(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(NetworkTimeout))

	// Auth if configured
	if s.auth != nil {
		challenge := uuid.New().String()
		if err := sendJSON(conn, ServerMessage{Type: "challenge", UUID: challenge}); err != nil {
			return err
		}
		var msg ClientMessage
		if err := recvJSON(conn, &msg); err != nil {
			return err
		}
		if msg.Type != "authenticate" || !s.auth.Validate(challenge, msg.Auth) {
			return fmt.Errorf("auth failed")
		}
	}

	var accept ClientMessage
	if err := recvJSON(conn, &accept); err != nil {
		return err
	}
	if accept.Type != "accept" {
		return fmt.Errorf("expected accept, got %s", accept.Type)
	}

	// Look up pending connection
	pending, ok := s.conns.LoadAndDelete(accept.UUID)
	if !ok {
		return fmt.Errorf("unknown connection: %s", accept.UUID)
	}

	// Proxy data bidirectionally
	remote := pending.(net.Conn)
	defer remote.Close()

	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(conn, remote)
		done <- err
	}()
	go func() {
		_, err := io.Copy(remote, conn)
		done <- err
	}()

	<-done
	return nil
}

func (s *TunnelServer) createListener(requestedPort uint16) (net.Listener, uint16, error) {
	if requestedPort > 0 {
		addr := fmt.Sprintf("%s:%d", s.bindAddr, requestedPort)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, 0, err
		}
		return l, requestedPort, nil
	}

	diff := s.portRange[1] - s.portRange[0]
	if diff == 0 {
		addr := fmt.Sprintf("%s:%d", s.bindAddr, s.portRange[0])
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, 0, err
		}
		return l, s.portRange[0], nil
	}

	// Random port from range
	for i := 0; i < 150; i++ {
		port := s.portRange[0] + randUint16()%(diff+1)
		addr := fmt.Sprintf("%s:%d", s.bindAddr, port)
		l, err := net.Listen("tcp", addr)
		if err == nil {
			return l, port, nil
		}
	}
	return nil, 0, fmt.Errorf("no available ports in range %d-%d", s.portRange[0], s.portRange[1])
}

func sendJSON(conn net.Conn, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, 0) // null delimiter
	conn.SetWriteDeadline(time.Now().Add(NetworkTimeout))
	_, err = conn.Write(data)
	return err
}

func recvJSON(conn net.Conn, v interface{}) error {
	conn.SetReadDeadline(time.Now().Add(NetworkTimeout))
	var data []byte
	buf := make([]byte, 1)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			return err
		}
		if buf[0] == 0 {
			break
		}
		data = append(data, buf[0])
		if len(data) > MaxFrameLength {
			return fmt.Errorf("frame size exceeded maximum length")
		}
	}
	return json.Unmarshal(data, v)
}

func randUint16() uint16 {
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return binary.BigEndian.Uint16(b)
}
