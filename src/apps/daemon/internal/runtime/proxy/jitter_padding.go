package proxy

import (
	"crypto/rand"
	"math/big"
	"net"
	"time"
)

// PsiphonJitterConn wraps a net.Conn and appends random noise/padding
// to the initial packets to prevent pattern matching by DPI devices.
type PsiphonJitterConn struct {
	net.Conn
	packetCounter int
}

// NewPsiphonJitterConn wraps a connection with jitter and padding.
func NewPsiphonJitterConn(c net.Conn) *PsiphonJitterConn {
	return &PsiphonJitterConn{Conn: c}
}

// Write intercepts the first three packet writes and injects random padding with connection delays.
func (c *PsiphonJitterConn) Write(b []byte) (int, error) {
	c.packetCounter++
	if c.packetCounter <= 3 {
		// Generate random padding size between 32 and 96 bytes
		paddingSize := 32 + getRandomInt(64)
		padding := make([]byte, paddingSize)
		_, _ = rand.Read(padding)

		// Write dummy padding data to create noise
		_, _ = c.Conn.Write(padding)

		// Add a slight latency jitter delay between 5 and 20 ms
		jitterDelay := 5 + getRandomInt(15)
		time.Sleep(time.Duration(jitterDelay) * time.Millisecond)
	}
	return c.Conn.Write(b)
}

func getRandomInt(max int64) int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}

// DustObfuscatorConn implements Dust-style obfuscation with Markov-chain timing delays and Huffman-like length padding.
type DustObfuscatorConn struct {
	net.Conn
	state         int // 0 = Idle, 1 = Active, 2 = Burst
	packetCounter int
}

func NewDustObfuscatorConn(c net.Conn) *DustObfuscatorConn {
	return &DustObfuscatorConn{Conn: c}
}

func (c *DustObfuscatorConn) Write(b []byte) (int, error) {
	c.packetCounter++

	// 1. Simulate Markov-state transition for inter-packet delay
	c.transitionState()
	delay := c.getDelayForState()
	if delay > 0 {
		time.Sleep(delay)
	}

	// 2. Perform length shaping (Huffman padding emulation)
	targetLen := c.getShapedLength(len(b))
	if targetLen > len(b) {
		padding := make([]byte, targetLen-len(b))
		_, _ = rand.Read(padding)
		_, _ = c.Conn.Write(padding)
	}

	return c.Conn.Write(b)
}

func (c *DustObfuscatorConn) transitionState() {
	r := getRandomInt(100)
	switch c.state {
	case 0: // Idle
		if r < 30 {
			c.state = 1
		} else if r < 40 {
			c.state = 2
		}
	case 1: // Active
		if r < 20 {
			c.state = 0
		} else if r < 40 {
			c.state = 2
		}
	case 2: // Burst
		if r < 50 {
			c.state = 0
		} else if r < 80 {
			c.state = 1
		}
	}
}

func (c *DustObfuscatorConn) getDelayForState() time.Duration {
	switch c.state {
	case 0:
		return time.Duration(10+getRandomInt(40)) * time.Millisecond // 10-50ms
	case 1:
		return time.Duration(2+getRandomInt(8)) * time.Millisecond // 2-10ms
	case 2:
		return time.Duration(getRandomInt(3)) * time.Millisecond // 0-3ms
	default:
		return 0
	}
}

func (c *DustObfuscatorConn) getShapedLength(originalLen int) int {
	boundaries := []int{16, 32, 64, 128, 256, 512, 1024, 1500}
	for _, b := range boundaries {
		if b >= originalLen {
			return b
		}
	}
	return originalLen
}
