package proxy

import (
	"context"
	"net"
	"sync"
	"syscall"
)

// GracefulListener wraps a net.Listener with SO_REUSEADDR/SO_REUSEPORT to allow hot-swapping
// of network listeners without dropping active connections.
type GracefulListener struct {
	net.Listener
	conns  map[net.Conn]struct{}
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func NewGracefulListener(network, addr string) (*GracefulListener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}

	ln, err := lc.Listen(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}

	return &GracefulListener{
		Listener: ln,
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

func (l *GracefulListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	l.conns[conn] = struct{}{}
	l.mu.Unlock()

	l.wg.Add(1)
	wrapped := &gracefulConn{
		Conn: conn,
		l:    l,
	}
	return wrapped, nil
}

func (l *GracefulListener) CloseGracefully() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()

	err := l.Listener.Close()
	l.wg.Wait()
	return err
}

type gracefulConn struct {
	net.Conn
	l    *GracefulListener
	once sync.Once
}

func (c *gracefulConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.l.mu.Lock()
		delete(c.l.conns, c.Conn)
		c.l.mu.Unlock()
		c.l.wg.Done()
	})
	return err
}
