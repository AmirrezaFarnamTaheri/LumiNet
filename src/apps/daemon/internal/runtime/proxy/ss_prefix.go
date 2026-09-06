package proxy

import (
	"encoding/hex"
	"fmt"
	"net"
)

// SSPrefixConn wraps a net.Conn and prepends a fixed prefix to the FIRST Write.
type SSPrefixConn struct {
	net.Conn
	prefix     []byte
	prefixSent bool
}

// NewSSPrefixConn wraps conn to inject prefix bytes before the first payload write.
// prefixHex is hex-encoded (e.g. "deadbeef"). Empty string means no injection.
func NewSSPrefixConn(conn net.Conn, prefixHex string) (net.Conn, error) {
	if prefixHex == "" {
		return conn, nil
	}
	b, err := hex.DecodeString(prefixHex)
	if err != nil {
		return nil, fmt.Errorf("ss_prefix: invalid prefix hex %q: %w", prefixHex, err)
	}
	if len(b) == 0 {
		return conn, nil
	}
	return &SSPrefixConn{Conn: conn, prefix: b}, nil
}

func (c *SSPrefixConn) Write(b []byte) (int, error) {
	if !c.prefixSent {
		c.prefixSent = true
		buf := make([]byte, 0, len(c.prefix)+len(b))
		buf = append(buf, c.prefix...)
		buf = append(buf, b...)
		_, err := c.Conn.Write(buf)
		if err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return c.Conn.Write(b)
}

// WrapSSPrefix wraps conn with prefix injection if cfg.ShadowsocksPrefix is non-empty.
func WrapSSPrefix(conn net.Conn, cfg *EvasionConfig) (net.Conn, error) {
	if cfg.ShadowsocksPrefix == "" {
		return conn, nil
	}
	return NewSSPrefixConn(conn, cfg.ShadowsocksPrefix)
}
