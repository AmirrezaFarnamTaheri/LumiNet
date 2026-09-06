package proxy

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
)

const kFirstPaddings = 8

// NaivePaddingConn wraps a net.Conn with NaiveProxy deterministic frame padding.
type NaivePaddingConn struct {
	net.Conn
	writeCount int
	readCount  int
	readBuffer []byte
}

// NewNaivePaddingConn creates a new NaivePaddingConn.
func NewNaivePaddingConn(conn net.Conn) *NaivePaddingConn {
	return &NaivePaddingConn{
		Conn: conn,
	}
}

// Write implements net.Conn.Write.
// It wraps payloads with padding for the first kFirstPaddings writes.
func (c *NaivePaddingConn) Write(b []byte) (int, error) {
	if c.writeCount >= kFirstPaddings {
		return c.Conn.Write(b)
	}

	c.writeCount++
	origLen := len(b)
	if origLen > 65535 {
		return 0, fmt.Errorf("payload too large for padded frame: %d", origLen)
	}

	// Generate random padding size in range [0, 255]
	var padLen int
	nBig, err := rand.Int(rand.Reader, big.NewInt(256))
	if err == nil {
		padLen = int(nBig.Int64())
	} else {
		padLen = 32 // Safe fallback
	}

	// Frame structure:
	// [Original Data Size High (1)] [Original Data Size Low (1)] [Padding Size (1)] [Original Data] [Zero Padding]
	frame := make([]byte, 3+origLen+padLen)
	binary.BigEndian.PutUint16(frame[0:2], uint16(origLen))
	frame[2] = byte(padLen)
	copy(frame[3:3+origLen], b)
	// frame[3+origLen:] is automatically zeroes

	_, err = c.Conn.Write(frame)
	if err != nil {
		return 0, err
	}

	return origLen, nil
}

// Read implements net.Conn.Read.
// It parses the padded frames for the first kFirstPaddings reads.
func (c *NaivePaddingConn) Read(b []byte) (int, error) {
	if c.readCount >= kFirstPaddings {
		if len(c.readBuffer) > 0 {
			n := copy(b, c.readBuffer)
			c.readBuffer = c.readBuffer[n:]
			return n, nil
		}
		return c.Conn.Read(b)
	}

	// Parse padded frame header
	c.readCount++
	header := make([]byte, 3)
	_, err := io.ReadFull(c.Conn, header)
	if err != nil {
		return 0, err
	}

	origLen := int(binary.BigEndian.Uint16(header[0:2]))
	padLen := int(header[2])

	fullPayload := make([]byte, origLen+padLen)
	_, err = io.ReadFull(c.Conn, fullPayload)
	if err != nil {
		return 0, err
	}

	origBytes := fullPayload[:origLen]
	n := copy(b, origBytes)
	if n < origLen {
		c.readBuffer = append(c.readBuffer, origBytes[n:]...)
	}

	return n, nil
}

// WriteEndStream writes a padded END_STREAM DATA frame (mimicking HTTP/2 browser HEADERS)
// of length [48, 72] containing zero bytes to obscure connection teardowns.
func (c *NaivePaddingConn) WriteEndStream() error {
	var size int
	nBig, err := rand.Int(rand.Reader, big.NewInt(25)) // 72 - 48 + 1 = 25
	if err == nil {
		size = 48 + int(nBig.Int64())
	} else {
		size = 60
	}

	decoyFrame := make([]byte, size)
	_, err = c.Conn.Write(decoyFrame)
	return err
}
