package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// TUIC version and command types
const (
	TuicVersion         = 0x05
	TuicCmdAuthenticate = 0x00
	TuicCmdConnect      = 0x01
	TuicCmdPacket       = 0x02
	TuicCmdDissociate   = 0x03
	TuicCmdHeartbeat    = 0x04
)

// Target address types
const (
	TuicAddrTypeDomain = 0x00
	TuicAddrTypeIPv4   = 0x01
	TuicAddrTypeIPv6   = 0x02
	TuicAddrTypeNone   = 0xff
)

// TuicSession is a bounded TUIC v5 command-frame codec over an already-established
// byte stream. It does not establish the protocol's required QUIC transport and
// therefore must not be used as a standalone TUIC dialer. Sending Authenticate is
// also not proof that the peer accepted authentication.
type TuicSession struct {
	mu       sync.Mutex
	conn     net.Conn
	uuid     [16]byte
	token    [32]byte
	authSent bool
}

// NewTuicSession creates a new TUIC connection wrapper.
func NewTuicSession(conn net.Conn, uuid [16]byte, token [32]byte) *TuicSession {
	return &TuicSession{
		conn:  conn,
		uuid:  uuid,
		token: token,
	}
}

// WriteAuthenticate writes the initial Authenticate frame over the stream.
func (s *TuicSession) WriteAuthenticate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf := new(bytes.Buffer)
	buf.WriteByte(TuicVersion)
	buf.WriteByte(TuicCmdAuthenticate)
	buf.Write(s.uuid[:])
	buf.Write(s.token[:])

	_, err := s.conn.Write(buf.Bytes())
	if err == nil {
		s.authSent = true
	}
	return err
}

// AuthenticationFrameSent reports whether this client successfully wrote the
// Authenticate frame. TUIC v5 has no standard authentication response, so this
// must not be interpreted as peer acceptance.
func (s *TuicSession) AuthenticationFrameSent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authSent
}

// WriteConnect writes a target TCP connection request connect frame.
func (s *TuicSession) WriteConnect(addrType byte, host string, port uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf := new(bytes.Buffer)
	buf.WriteByte(TuicVersion)
	buf.WriteByte(TuicCmdConnect)

	// Encode Address
	buf.WriteByte(addrType)
	switch addrType {
	case TuicAddrTypeDomain:
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("TUIC domain length must be 1..255 bytes: %d", len(host))
		}
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	case TuicAddrTypeIPv4:
		ip := net.ParseIP(host).To4()
		if ip == nil {
			return errors.New("invalid IPv4 address")
		}
		buf.Write(ip)
	case TuicAddrTypeIPv6:
		ip := net.ParseIP(host).To16()
		if ip == nil {
			return errors.New("invalid IPv6 address")
		}
		buf.Write(ip)
	default:
		return fmt.Errorf("unsupported address type: %d", addrType)
	}

	_ = binary.Write(buf, binary.BigEndian, port)

	_, err := s.conn.Write(buf.Bytes())
	return err
}

// WritePacket writes a UDP payload fragment command frame.
func (s *TuicSession) WritePacket(assocID, pktID uint16, fragTotal, fragID byte, targetHost string, targetPort uint16, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if fragTotal == 0 || fragID >= fragTotal {
		return fmt.Errorf("invalid TUIC fragment index %d/%d", fragID, fragTotal)
	}
	if len(payload) > 0xffff {
		return fmt.Errorf("TUIC packet payload exceeds uint16 wire limit: %d", len(payload))
	}
	if fragID == 0 && (len(targetHost) == 0 || len(targetHost) > 255) {
		return fmt.Errorf("TUIC domain length must be 1..255 bytes: %d", len(targetHost))
	}

	buf := new(bytes.Buffer)
	buf.WriteByte(TuicVersion)
	buf.WriteByte(TuicCmdPacket)

	_ = binary.Write(buf, binary.BigEndian, assocID)
	_ = binary.Write(buf, binary.BigEndian, pktID)
	buf.WriteByte(fragTotal)
	buf.WriteByte(fragID)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(payload)))

	// For first fragment, specify address
	if fragID == 0 {
		buf.WriteByte(TuicAddrTypeDomain)
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
		_ = binary.Write(buf, binary.BigEndian, targetPort)
	} else {
		buf.WriteByte(TuicAddrTypeNone)
	}

	buf.Write(payload)

	_, err := s.conn.Write(buf.Bytes())
	return err
}

// WriteHeartbeat writes a heartbeat keepalive frame: [version:1][cmd:1]
func (s *TuicSession) WriteHeartbeat() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.conn.Write([]byte{TuicVersion, TuicCmdHeartbeat})
	return err
}

// WriteDissociate writes a UDP association teardown frame: [version:1][cmd:1][assocID:2]
func (s *TuicSession) WriteDissociate(assocID uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf := make([]byte, 4)
	buf[0] = TuicVersion
	buf[1] = TuicCmdDissociate
	buf[2] = byte(assocID >> 8)
	buf[3] = byte(assocID)
	_, err := s.conn.Write(buf)
	return err
}

// ReadCommandHeader reads the prefix header of a TUIC command.
func ReadCommandHeader(r io.Reader) (ver, cmdType byte, err error) {
	buf := make([]byte, 2)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return 0, 0, err
	}
	return buf[0], buf[1], nil
}
