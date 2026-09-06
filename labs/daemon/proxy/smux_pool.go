package proxy

import (
	"net"
	"sync"
	"time"
)

type SMUXSession struct {
	conn net.Conn
	id   uint32
}

// SMUXPool multiplexes multiple logical connections over a single transport stream.
type SMUXPool struct {
	mu       sync.Mutex
	sessions map[string]*SMUXSession
}

func NewSMUXPool() *SMUXPool {
	return &SMUXPool{
		sessions: make(map[string]*SMUXSession),
	}
}

func (p *SMUXPool) GetOrDial(addr string, timeout time.Duration) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if sess, ok := p.sessions[addr]; ok {
		// Verify if the connection is still active and readable
		_ = sess.conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
		var one [1]byte
		if _, err := sess.conn.Read(one[:]); err != nil {
			if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
				sess.conn.Close()
				delete(p.sessions, addr)
			}
		}
	}

	if sess, ok := p.sessions[addr]; ok {
		return sess.conn, nil
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}

	sess := &SMUXSession{
		conn: conn,
		id:   uint32(time.Now().UnixNano()),
	}
	p.sessions[addr] = sess
	return conn, nil
}
