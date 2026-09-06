package proxy

import (
	"context"
	"encoding/binary"
	"net"
	"sync"

	"github.com/gorilla/websocket"
)

// ReverseTunnelServer multiplexes connections from a local listener over a WebSocket connection.
type ReverseTunnelServer struct {
	mu         sync.Mutex
	wsConn     *websocket.Conn
	listener   net.Listener
	channels   map[uint32]net.Conn
	nextChanID uint32
	closed     bool
}

func NewReverseTunnelServer(wsConn *websocket.Conn, localAddr string) (*ReverseTunnelServer, error) {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return nil, err
	}
	return &ReverseTunnelServer{
		wsConn:   wsConn,
		listener: ln,
		channels: make(map[uint32]net.Conn),
	}, nil
}

func (s *ReverseTunnelServer) Start(ctx context.Context) {
	go s.readLoop()
	go s.acceptLoop(ctx)
}

func (s *ReverseTunnelServer) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	s.listener.Close()
	s.wsConn.Close()

	s.mu.Lock()
	for _, conn := range s.channels {
		conn.Close()
	}
	s.mu.Unlock()
}

func (s *ReverseTunnelServer) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.mu.Lock()
		chanID := s.nextChanID
		s.nextChanID++
		s.channels[chanID] = conn
		s.mu.Unlock()

		header := make([]byte, 5)
		header[0] = 1
		binary.BigEndian.PutUint32(header[1:], chanID)

		s.mu.Lock()
		err = s.wsConn.WriteMessage(websocket.BinaryMessage, header)
		s.mu.Unlock()

		if err != nil {
			conn.Close()
			return
		}

		go s.handleLocalConn(chanID, conn)
	}
}

func (s *ReverseTunnelServer) handleLocalConn(chanID uint32, conn net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			frame := make([]byte, 5+n)
			frame[0] = 2
			binary.BigEndian.PutUint32(frame[1:], chanID)
			copy(frame[5:], buf[:n])

			s.mu.Lock()
			writeErr := s.wsConn.WriteMessage(websocket.BinaryMessage, frame)
			s.mu.Unlock()

			if writeErr != nil {
				conn.Close()
				return
			}
		}
		if err != nil {
			break
		}
	}

	s.closeChannel(chanID)
}

func (s *ReverseTunnelServer) closeChannel(chanID uint32) {
	s.mu.Lock()
	conn, ok := s.channels[chanID]
	if ok {
		delete(s.channels, chanID)
		conn.Close()
	}
	s.mu.Unlock()

	header := make([]byte, 5)
	header[0] = 3
	binary.BigEndian.PutUint32(header[1:], chanID)

	s.mu.Lock()
	_ = s.wsConn.WriteMessage(websocket.BinaryMessage, header)
	s.mu.Unlock()
}

func (s *ReverseTunnelServer) readLoop() {
	for {
		_, data, err := s.wsConn.ReadMessage()
		if err != nil {
			s.Close()
			return
		}

		if len(data) < 5 {
			continue
		}

		frameType := data[0]
		chanID := binary.BigEndian.Uint32(data[1:5])

		s.mu.Lock()
		conn, ok := s.channels[chanID]
		s.mu.Unlock()

		switch frameType {
		case 2: // DATA
			if ok {
				_, _ = conn.Write(data[5:])
			}
		case 3: // CLOSE
			if ok {
				s.mu.Lock()
				delete(s.channels, chanID)
				s.mu.Unlock()
				conn.Close()
			}
		}
	}
}
