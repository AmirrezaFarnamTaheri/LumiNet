package tlsfragment

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type captureConn struct{ writes [][]byte }

func (c *captureConn) Read([]byte) (int, error) { return 0, nil }
func (c *captureConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return nil }
func (c *captureConn) RemoteAddr() net.Addr             { return nil }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

func TestFragmentStrategiesAndSecondWrite(t *testing.T) {
	none := &captureConn{}
	if WrapUTLSFragmentConn(none, UTLSFragmentConfig{Strategy: StrategyNone}) != none {
		t.Fatal("none strategy must return original conn")
	}
	half := &captureConn{}
	_, _ = WrapUTLSFragmentConn(half, UTLSFragmentConfig{Strategy: StrategyHalf}).Write([]byte("abcdef"))
	if len(half.writes) != 2 || !bytes.Equal(half.writes[0], []byte("abc")) || !bytes.Equal(half.writes[1], []byte("def")) {
		t.Fatalf("half=%q", half.writes)
	}
	multi := &captureConn{}
	conn := WrapUTLSFragmentConn(multi, UTLSFragmentConfig{Strategy: StrategyMulti, ChunkSize: 2})
	_, _ = conn.Write([]byte("abcde"))
	_, _ = conn.Write([]byte("z"))
	if len(multi.writes) != 4 || !bytes.Equal(multi.writes[3], []byte("z")) {
		t.Fatalf("multi=%q", multi.writes)
	}
	tlsrec := &captureConn{}
	_, _ = WrapUTLSFragmentConn(tlsrec, UTLSFragmentConfig{Strategy: StrategyTlsRecordFrag}).Write([]byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04})
	if len(tlsrec.writes) != 2 {
		t.Fatalf("tls records=%d", len(tlsrec.writes))
	}
}
