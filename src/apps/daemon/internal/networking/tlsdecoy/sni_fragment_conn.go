package tlsdecoy

import (
	"net"
	"time"
)

// FragmentConn wraps a net.Conn and intercepts the initial TLS ClientHello packet,
// splitting it into multiple TCP segments to desynchronize stateful DPI parsers.
type FragmentConn struct {
	net.Conn
	fragmented bool
	strategy   string
	delay      time.Duration
}

// NewFragmentConn creates a new FragmentConn wrapper.
func NewFragmentConn(conn net.Conn, strategy string, delay time.Duration) *FragmentConn {
	return &FragmentConn{
		Conn:     conn,
		strategy: strategy,
		delay:    delay,
	}
}

// Write intercepts the first TLS handshake write (ContentType=0x16, HandshakeType=0x01).
func (c *FragmentConn) Write(b []byte) (int, error) {
	if !c.fragmented && len(b) > 5 && b[0] == 0x16 && b[5] == 0x01 {
		c.fragmented = true
		return c.fragmentWrite(b)
	}
	return c.Conn.Write(b)
}

func (c *FragmentConn) fragmentWrite(data []byte) (int, error) {
	chunks := SplitClientHello(data, c.strategy)
	for i, chunk := range chunks {
		if _, err := c.Conn.Write(chunk); err != nil {
			return 0, err
		}
		if i < len(chunks)-1 && c.delay > 0 {
			time.Sleep(c.delay)
		}
	}
	return len(data), nil
}

// SplitClientHello splits a TLS ClientHello according to strategy:
// - "sni_split": splits at the midpoint of the SNI extension hostname.
// - "half": splits payload in half.
// - "multi": splits into 24-byte chunks.
func SplitClientHello(data []byte, strategy string) [][]byte {
	switch strategy {
	case "sni_split":
		offset, hostLen := FindSNIHostnameOffset(data)
		if offset > 0 && offset < len(data) {
			mid := offset
			if hostLen > 0 {
				mid = offset + hostLen/2
			} else {
				mid = offset + (len(data)-offset)/2
			}
			if mid <= 0 {
				mid = 1
			}
			if mid >= len(data) {
				mid = len(data) - 1
			}
			return [][]byte{data[:mid], data[mid:]}
		}
		return SplitHalf(data)
	case "half":
		return SplitHalf(data)
	case "multi":
		return SplitMulti(data, 24)
	default:
		return SplitHalf(data)
	}
}

// SplitHalf splits data into two equal slices.
func SplitHalf(data []byte) [][]byte {
	if len(data) <= 1 {
		return [][]byte{data}
	}
	mid := len(data) / 2
	return [][]byte{data[:mid], data[mid:]}
}

// SplitMulti splits data into fixed-size chunks.
func SplitMulti(data []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 {
		chunkSize = 24
	}
	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

// FindSNIHostnameOffset locates the byte offset and length where the SNI hostname string begins.
func FindSNIHostnameOffset(data []byte) (int, int) {
	if len(data) < 44 || data[0] != 0x16 {
		return -1, 0
	}

	pos := 5 + 4 // TLS record header (5) + handshake header (4)
	pos += 2     // client version
	pos += 32    // random

	if pos >= len(data) {
		return -1, 0
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(data) {
		return -1, 0
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	if pos+1 > len(data) {
		return -1, 0
	}
	compMethodsLen := int(data[pos])
	pos += 1 + compMethodsLen

	if pos+2 > len(data) {
		return -1, 0
	}
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	extensionsEnd := pos + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// Iterate extensions looking for SNI (Type 0x0000)
	for pos+4 <= extensionsEnd {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0x0000 && extLen > 0 {
			// SNI extension structure: list_length(2) + name_type(1) + hostname_length(2) + hostname
			if pos+5 <= extensionsEnd {
				hostLen := int(data[pos+3])<<8 | int(data[pos+4])
				hostStart := pos + 5
				if hostStart+hostLen <= len(data) {
					return hostStart, hostLen
				}
			}
		}
		pos += extLen
	}

	return -1, 0
}
