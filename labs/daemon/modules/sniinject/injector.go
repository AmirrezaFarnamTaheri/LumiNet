package sniinject

import (
	"errors"
	"net"
	"time"
)

// SplitConfig configures SNI TCP segment splitting parameters.
type SplitConfig struct {
	SplitOffset int
	Delay       time.Duration
}

// SplitClientHello splits the initial ClientHello TLS handshake payload into 2 segments.
func SplitClientHello(conn net.Conn, clientHello []byte, cfg SplitConfig) error {
	if conn == nil {
		return errors.New("nil net.Conn")
	}
	if len(clientHello) == 0 {
		return errors.New("empty ClientHello bytes")
	}

	splitAt := cfg.SplitOffset
	if splitAt <= 0 || splitAt >= len(clientHello) {
		splitAt = len(clientHello) / 2
	}

	segment1 := clientHello[:splitAt]
	segment2 := clientHello[splitAt:]

	// Write first segment
	if _, err := conn.Write(segment1); err != nil {
		return err
	}

	if cfg.Delay > 0 {
		time.Sleep(cfg.Delay)
	}

	// Write second segment
	_, err := conn.Write(segment2)
	return err
}
