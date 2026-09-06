package tlsfragment

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// FragmentationStrategy represents the technique used to split the ClientHello packet.
type FragmentationStrategy string

const (
	StrategyNone          FragmentationStrategy = "none"
	StrategySniSplit      FragmentationStrategy = "sni_split"
	StrategyHalf          FragmentationStrategy = "half"
	StrategyMulti         FragmentationStrategy = "multi"
	StrategyTlsRecordFrag FragmentationStrategy = "tls_record_frag"
)

// UTLSFragmentConfig configures handshake fragmentation.
type UTLSFragmentConfig struct {
	Strategy     FragmentationStrategy
	SleepBetween time.Duration
	ChunkSize    int // For StrategyMulti, defaults to 24
}

// WrapUTLSFragmentConn wraps a net.Conn to fragment the first TLS ClientHello write.
func WrapUTLSFragmentConn(conn net.Conn, cfg UTLSFragmentConfig) net.Conn {
	if cfg.Strategy == StrategyNone {
		return conn
	}
	return &utlsFragmentConn{
		Conn:       conn,
		cfg:        cfg,
		firstWrite: true,
	}
}

type utlsFragmentConn struct {
	net.Conn
	cfg        UTLSFragmentConfig
	firstWrite bool
}

// Write intercepts the first write call and fragments it according to the strategy.
func (c *utlsFragmentConn) Write(b []byte) (int, error) {
	if !c.firstWrite {
		return c.Conn.Write(b)
	}
	c.firstWrite = false

	if len(b) == 0 {
		return c.Conn.Write(b)
	}

	var fragments [][]byte
	switch c.cfg.Strategy {
	case StrategySniSplit:
		fragments = fragmentAtSNI(b)
	case StrategyHalf:
		mid := len(b) / 2
		fragments = [][]byte{b[:mid], b[mid:]}
	case StrategyMulti:
		fragments = fragmentMulti(b, c.cfg.ChunkSize)
	case StrategyTlsRecordFrag:
		fragments = tlsRecordFragment(b)
	default:
		fragments = [][]byte{b}
	}

	// Make sure we have TCP_NODELAY if it is a TCP connection
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	for i, frag := range fragments {
		if _, err := c.Conn.Write(frag); err != nil {
			return 0, fmt.Errorf("failed to write fragment %d: %w", i, err)
		}
		if c.cfg.SleepBetween > 0 && i < len(fragments)-1 {
			time.Sleep(c.cfg.SleepBetween)
		}
	}

	return len(b), nil
}

// findSNIOffset uses the canonical bounds-checked ClientHello parser.
// It returns the hostname offset and length, or (-1, 0) when SNI is absent or malformed.
func findSNIOffset(data []byte) (int, int) {
	start, end := SNIHostRange(data)
	if start == 0 && end == 0 {
		return -1, 0
	}
	return start, end - start
}

func fragmentAtSNI(data []byte) [][]byte {
	sniOffset, sniLen := findSNIOffset(data)
	if sniOffset < 0 {
		mid := len(data) / 2
		return [][]byte{data[:mid], data[mid:]}
	}
	splitPoint := sniOffset + sniLen/2
	return [][]byte{data[:splitPoint], data[splitPoint:]}
}

func fragmentMulti(data []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 {
		chunkSize = 24
	}
	var fragments [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		fragments = append(fragments, data[i:end])
	}
	return fragments
}

func tlsRecordFragment(data []byte) [][]byte {
	if len(data) < 6 || data[0] != 0x16 {
		return [][]byte{data}
	}
	recordVersion := data[1:3]
	handshakeData := data[5:]

	mid := len(handshakeData) / 2
	part1 := handshakeData[:mid]
	part2 := handshakeData[mid:]

	// Construct two separate TLS record layer wrappers (type 0x16)
	record1 := make([]byte, 5+len(part1))
	record1[0] = 0x16
	copy(record1[1:3], recordVersion)
	binary.BigEndian.PutUint16(record1[3:5], uint16(len(part1)))
	copy(record1[5:], part1)

	record2 := make([]byte, 5+len(part2))
	record2[0] = 0x16
	copy(record2[1:3], recordVersion)
	binary.BigEndian.PutUint16(record2[3:5], uint16(len(part2)))
	copy(record2[5:], part2)

	return [][]byte{record1, record2}
}
