
package diagnostics

import (
	"math/rand"
	"net"
	"time"
)

// LossyConn wraps an existing net.Conn to simulate packet drops and latency.
type LossyConn struct {
	net.Conn
	lossRate float64       // 0.0 to 1.0 (e.g. 0.1 for 10% loss)
	minDelay time.Duration // minimum artificial latency
	maxDelay time.Duration // maximum artificial latency
	rng      *rand.Rand
}

// NewLossyConn creates a new wrapped connection.
func NewLossyConn(conn net.Conn, lossRate float64, minDelay, maxDelay time.Duration) *LossyConn {
	return &LossyConn{
		Conn:     conn,
		lossRate: lossRate,
		minDelay: minDelay,
		maxDelay: maxDelay,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Read implements net.Conn.Read.
func (c *LossyConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, err
	}

	// Heuristically decide to drop the read packet to simulate inbound packet loss.
	if c.lossRate > 0 && c.rng.Float64() < c.lossRate {
		// Instead of returning error, we sleep and simulate a timeout or drop.
		time.Sleep(c.minDelay)
		return 0, &net.OpError{
			Op:   "read",
			Net:  c.Conn.RemoteAddr().Network(),
			Addr: c.Conn.RemoteAddr(),
			Err:  lossyError("packet dropped by simulation"),
		}
	}

	// Apply delay
	if c.minDelay > 0 {
		delay := c.minDelay
		if c.maxDelay > c.minDelay {
			delay += time.Duration(c.rng.Int63n(int64(c.maxDelay - c.minDelay)))
		}
		time.Sleep(delay)
	}

	return n, nil
}

// Write implements net.Conn.Write.
func (c *LossyConn) Write(b []byte) (int, error) {
	// Heuristically decide to drop the write packet to simulate outbound packet loss.
	if c.lossRate > 0 && c.rng.Float64() < c.lossRate {
		time.Sleep(c.minDelay)
		return 0, &net.OpError{
			Op:   "write",
			Net:  c.Conn.RemoteAddr().Network(),
			Addr: c.Conn.RemoteAddr(),
			Err:  lossyError("packet dropped by simulation"),
		}
	}

	// Apply delay
	if c.minDelay > 0 {
		delay := c.minDelay
		if c.maxDelay > c.minDelay {
			delay += time.Duration(c.rng.Int63n(int64(c.maxDelay - c.minDelay)))
		}
		time.Sleep(delay)
	}

	return c.Conn.Write(b)
}

type lossyError string

func (e lossyError) Error() string   { return string(e) }
func (e lossyError) Timeout() bool   { return true }
func (e lossyError) Temporary() bool { return true }
