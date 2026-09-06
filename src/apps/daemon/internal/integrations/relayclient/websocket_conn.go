package relayclient

import (
	"context"
	"net"
	"time"

	"github.com/gorilla/websocket"
	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
)

const (
	relayWebSocketReadLimit           int64 = 1 << 20
	relayWebSocketConfirmationTimeout       = 5 * time.Second
)

type WebSocketConn struct {
	*websocket.Conn
	readBuf []byte
	flow    *flowregistry.Handle
}

func configureRelayWebSocket(conn *websocket.Conn) {
	conn.SetReadLimit(relayWebSocketReadLimit)
}

func NewWebSocketConn(conn *websocket.Conn) *WebSocketConn {
	return newWebSocketConn(conn, "")
}

func NewObservedWebSocketConn(conn *websocket.Conn, destination string) *WebSocketConn {
	return newWebSocketConn(conn, destination)
}

func newWebSocketConn(conn *websocket.Conn, destination string) *WebSocketConn {
	configureRelayWebSocket(conn)
	s := &WebSocketConn{Conn: conn}
	if destination != "" {
		s.flow = registerRelayFlow("relay-serverless-ws", "serverless-websocket", destination, func(context.Context) error { return s.closeTransport() })
	}
	return s
}

func (s *WebSocketConn) Read(b []byte) (int, error) {
	if len(s.readBuf) > 0 {
		n := copy(b, s.readBuf)
		s.readBuf = s.readBuf[n:]
		addFlowDownload(s.flow, n)
		return n, nil
	}

	_, msg, err := s.ReadMessage()
	if err != nil {
		_ = s.closeTransport()
		closeFlowHandle(s.flow)
		return 0, err
	}

	n := copy(b, msg)
	if n < len(msg) {
		s.readBuf = msg[n:]
	}
	addFlowDownload(s.flow, n)
	return n, nil
}

func (s *WebSocketConn) Write(b []byte) (int, error) {
	if err := s.WriteMessage(websocket.BinaryMessage, b); err != nil {
		_ = s.closeTransport()
		closeFlowHandle(s.flow)
		return 0, err
	}
	addFlowUpload(s.flow, len(b))
	return len(b), nil
}

func (s *WebSocketConn) closeTransport() error {
	if s == nil || s.Conn == nil {
		return nil
	}
	return s.Conn.Close()
}

func (s *WebSocketConn) Close() error {
	err := s.closeTransport()
	closeFlowHandle(s.flow)
	return err
}

func (s *WebSocketConn) LocalAddr() net.Addr {
	if s == nil || s.Conn == nil || s.Conn.NetConn() == nil {
		return nil
	}
	return s.Conn.NetConn().LocalAddr()
}

func (s *WebSocketConn) RemoteAddr() net.Addr {
	if s == nil || s.Conn == nil || s.Conn.NetConn() == nil {
		return nil
	}
	return s.Conn.NetConn().RemoteAddr()
}

func (s *WebSocketConn) SetDeadline(t time.Time) error {
	if err := s.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return s.Conn.SetWriteDeadline(t)
}

func (s *WebSocketConn) SetReadDeadline(t time.Time) error {
	return s.Conn.SetReadDeadline(t)
}

func (s *WebSocketConn) SetWriteDeadline(t time.Time) error {
	return s.Conn.SetWriteDeadline(t)
}
