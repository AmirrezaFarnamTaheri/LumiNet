package proxy

import (
	"fmt"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

const proxyWebSocketReadLimit int64 = 1 << 20

func configureProxyWebSocket(conn *websocket.Conn) {
	conn.SetReadLimit(proxyWebSocketReadLimit)
}

func proxyWebSocketLocalAddr(conn *websocket.Conn) net.Addr {
	if conn == nil || conn.NetConn() == nil {
		return nil
	}
	return conn.NetConn().LocalAddr()
}

func proxyWebSocketRemoteAddr(conn *websocket.Conn) net.Addr {
	if conn == nil || conn.NetConn() == nil {
		return nil
	}
	return conn.NetConn().RemoteAddr()
}

func proxyWebSocketSetDeadline(conn *websocket.Conn, deadline time.Time) error {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return err
	}
	return conn.SetWriteDeadline(deadline)
}

type vlessWSResponseState struct {
	headerComplete bool
	headerBuf      []byte
}

// consume accepts a complete WebSocket binary message and converts the initial
// VLESS response preface into stream semantics. The preface is consumed exactly
// once, may span multiple WebSocket messages, and is bounded by the one-byte
// VLESS addons length field (257 bytes total).
func (s *vlessWSResponseState) consume(msg []byte) ([]byte, bool, error) {
	if s.headerComplete {
		return msg, len(msg) > 0, nil
	}

	if len(s.headerBuf)+len(msg) > 257 {
		return nil, false, fmt.Errorf("vless response header exceeds protocol bound")
	}
	s.headerBuf = append(s.headerBuf, msg...)
	if len(s.headerBuf) < 2 {
		return nil, false, nil
	}
	if s.headerBuf[0] != 0 {
		return nil, false, fmt.Errorf("unexpected vless response version: %d", s.headerBuf[0])
	}

	headerLen := 2 + int(s.headerBuf[1])
	if len(s.headerBuf) < headerLen {
		return nil, false, nil
	}

	payload := append([]byte(nil), s.headerBuf[headerLen:]...)
	s.headerBuf = nil
	s.headerComplete = true
	return payload, len(payload) > 0, nil
}
