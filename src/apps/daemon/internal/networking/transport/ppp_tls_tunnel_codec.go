package transport

import (
	"encoding/binary"
	"errors"
)

// PppProtocol identifies the encapsulated layer 3 or control protocol
type PppProtocol uint16

const (
	PppProtocolIPv4 PppProtocol = 0x0021
	PppProtocolIPv6 PppProtocol = 0x0057
	PppProtocolLCP  PppProtocol = 0xC021
	PppProtocolIPCP PppProtocol = 0x8021
)

// PppTlsTunnelCodec frames and unframes Point-to-Point Protocol frames over TLS connections
type PppTlsTunnelCodec struct {
	enableHDLC bool
}

// NewPppTlsTunnelCodec creates a new PPP over TLS codec
func NewPppTlsTunnelCodec(enableHDLC bool) *PppTlsTunnelCodec {
	return &PppTlsTunnelCodec{
		enableHDLC: enableHDLC,
	}
}

// EncodeFrame wraps PPP protocol and payload with 2-byte length and optional HDLC framing
func (c *PppTlsTunnelCodec) EncodeFrame(proto PppProtocol, payload []byte) []byte {
	var body []byte
	if c.enableHDLC {
		body = append(body, 0xFF, 0x03) // HDLC All-Stations Broadcast + Unnumbered Info
	}
	var protoBytes [2]byte
	binary.BigEndian.PutUint16(protoBytes[:], uint16(proto))
	body = append(body, protoBytes[:]...)
	body = append(body, payload...)

	// Prefix with 2-byte frame length
	frame := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(body)))
	copy(frame[2:], body)
	return frame
}

// DecodeFrame extracts PPP protocol and payload from TLS stream buffer
func (c *PppTlsTunnelCodec) DecodeFrame(data []byte) (PppProtocol, []byte, error) {
	if len(data) < 2 {
		return 0, nil, errors.New("frame too short for length header")
	}

	frameLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+frameLen {
		return 0, nil, errors.New("incomplete frame body")
	}

	body := data[2 : 2+frameLen]
	offset := 0
	if c.enableHDLC {
		if len(body) < 2 || body[0] != 0xFF || body[1] != 0x03 {
			return 0, nil, errors.New("invalid HDLC header")
		}
		offset = 2
	}

	if len(body) < offset+2 {
		return 0, nil, errors.New("frame body missing protocol bytes")
	}

	proto := PppProtocol(binary.BigEndian.Uint16(body[offset : offset+2]))
	payload := body[offset+2:]
	return proto, payload, nil
}
