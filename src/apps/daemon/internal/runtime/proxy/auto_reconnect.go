package proxy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrMaxReconnectExceeded is returned when all reconnect attempts are exhausted.
var ErrMaxReconnectExceeded = errors.New("auto-reconnect: max attempts exceeded")

// DialFunc is the factory used to create a new connection on reconnect.
type DialFunc func(ctx context.Context) (net.Conn, error)

// ReconnectableConn wraps a net.Conn and transparently re-dials on failure.
type ReconnectableConn struct {
	mu       sync.RWMutex
	conn     net.Conn
	dialFn   DialFunc
	maxTries int   // 0 = unlimited
	baseMs   int   // base delay in ms (exponential backoff)
	closed   int32 // atomic flag
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewReconnectableConn creates a ReconnectableConn with an already-established
// underlying connection. maxTries=0 means unlimited retries.
func NewReconnectableConn(ctx context.Context, initial net.Conn, dial DialFunc, maxTries, baseMs int) *ReconnectableConn {
	if baseMs <= 0 {
		baseMs = 500
	}
	child, cancel := context.WithCancel(ctx)
	return &ReconnectableConn{
		conn:     initial,
		dialFn:   dial,
		maxTries: maxTries,
		baseMs:   baseMs,
		ctx:      child,
		cancel:   cancel,
	}
}

func (r *ReconnectableConn) reconnect() error {
	var attempt int
	for {
		if atomic.LoadInt32(&r.closed) == 1 {
			return ErrMaxReconnectExceeded
		}
		if r.maxTries > 0 && attempt >= r.maxTries {
			return fmt.Errorf("%w (tried %d times)", ErrMaxReconnectExceeded, attempt)
		}

		// Exponential backoff capped at 30 s
		delayMs := float64(r.baseMs) * math.Pow(1.5, float64(attempt))
		if delayMs > 30_000 {
			delayMs = 30_000
		}
		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-time.After(time.Duration(delayMs) * time.Millisecond):
		}

		newConn, err := r.dialFn(r.ctx)
		if err != nil {
			attempt++
			continue
		}

		r.mu.Lock()
		if r.conn != nil {
			_ = r.conn.Close()
		}
		r.conn = newConn
		r.mu.Unlock()
		return nil
	}
}

func (r *ReconnectableConn) Read(b []byte) (int, error) {
	for {
		r.mu.RLock()
		c := r.conn
		r.mu.RUnlock()

		n, err := c.Read(b)
		if err == nil {
			return n, nil
		}
		if atomic.LoadInt32(&r.closed) == 1 {
			return 0, err
		}
		if rerr := r.reconnect(); rerr != nil {
			return 0, rerr
		}
	}
}

func (r *ReconnectableConn) Write(b []byte) (int, error) {
	for {
		r.mu.RLock()
		c := r.conn
		r.mu.RUnlock()

		n, err := c.Write(b)
		if err == nil {
			return n, nil
		}
		if atomic.LoadInt32(&r.closed) == 1 {
			return 0, err
		}
		if rerr := r.reconnect(); rerr != nil {
			return 0, rerr
		}
	}
}

func (r *ReconnectableConn) Close() error {
	if atomic.CompareAndSwapInt32(&r.closed, 0, 1) {
		r.cancel()
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.conn != nil {
			return r.conn.Close()
		}
	}
	return nil
}

func (r *ReconnectableConn) LocalAddr() net.Addr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.conn != nil {
		return r.conn.LocalAddr()
	}
	return nil
}

func (r *ReconnectableConn) RemoteAddr() net.Addr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.conn != nil {
		return r.conn.RemoteAddr()
	}
	return nil
}

func (r *ReconnectableConn) SetDeadline(t time.Time) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.conn != nil {
		return r.conn.SetDeadline(t)
	}
	return nil
}

func (r *ReconnectableConn) SetReadDeadline(t time.Time) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.conn != nil {
		return r.conn.SetReadDeadline(t)
	}
	return nil
}

func (r *ReconnectableConn) SetWriteDeadline(t time.Time) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.conn != nil {
		return r.conn.SetWriteDeadline(t)
	}
	return nil
}

// WrapIfAutoReconnect wraps conn in a ReconnectableConn if cfg.AutoReconnectEnabled is true.
// Otherwise returns conn unchanged.
func WrapIfAutoReconnect(ctx context.Context, conn net.Conn, cfg *EvasionConfig, dial DialFunc) net.Conn {
	if !cfg.AutoReconnectEnabled {
		return conn
	}
	return NewReconnectableConn(ctx, conn, dial, cfg.AutoReconnectMaxTries, cfg.AutoReconnectDelayMs)
}
