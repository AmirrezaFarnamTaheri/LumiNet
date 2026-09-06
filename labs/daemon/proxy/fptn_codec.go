// Package proxy implements packet tunneling protocol encodings.
// Ported from: fptn-master (src/fptn-protocol-lib/protocol/protocol.proto)
// Target path: server/internal/proxy/fptn_codec.go

package proxy

import (
	"errors"
	"fmt"
)

// FPTNMessageType defines the packet message types.
type FPTNMessageType int32

const (
	FPTNMsgError        FPTNMessageType = 0
	FPTNMsgIPPacket     FPTNMessageType = 1
	FPTNMsgIPAssignment FPTNMessageType = 2
	FPTNMsgBatchPacket  FPTNMessageType = 3
)

// FPTNMessage represents a decoded FPTN protocol message envelope.
type FPTNMessage struct {
	Version      int32
	Type         FPTNMessageType
	IPv4Address  string
	IPv6Address  string
	BatchPackets [][]byte
	ErrorMsg     string
}

// FPTNPacketCodec provides low-level serialization for FPTN Protobuf packets.
type FPTNPacketCodec struct{}

// NewFPTNPacketCodec creates a new codec helper.
func NewFPTNPacketCodec() *FPTNPacketCodec {
	return &FPTNPacketCodec{}
}

// Decode parses a raw byte slice into an FPTNMessage.
func (c *FPTNPacketCodec) Decode(buf []byte) (*FPTNMessage, error) {
	msg := &FPTNMessage{Version: 1}
	idx := 0
	limit := len(buf)

	for idx < limit {
		tag, n := decodeVarint(buf[idx:])
		if n == 0 {
			return nil, errors.New("malformed protobuf tag")
		}
		idx += n

		fieldNum := tag >> 3
		wireType := tag & 0x07

		switch fieldNum {
		case 1: // protocol_version (varint)
			if wireType != 0 {
				return nil, fmt.Errorf("unexpected wire type for field 1: %d", wireType)
			}
			val, n := decodeVarint(buf[idx:])
			if n == 0 {
				return nil, errors.New("malformed varint for field 1")
			}
			msg.Version = int32(val)
			idx += n

		case 2: // msg_type (varint)
			if wireType != 0 {
				return nil, fmt.Errorf("unexpected wire type for field 2: %d", wireType)
			}
			val, n := decodeVarint(buf[idx:])
			if n == 0 {
				return nil, errors.New("malformed varint for field 2")
			}
			msg.Type = FPTNMessageType(val)
			idx += n

		case 3: // error (ErrorMessage, length-delimited)
			if wireType != 2 {
				return nil, fmt.Errorf("unexpected wire type for field 3: %d", wireType)
			}
			length, n := decodeVarint(buf[idx:])
			if n == 0 {
				return nil, errors.New("malformed length for field 3")
			}
			idx += n
			if idx+int(length) > limit {
				return nil, errors.New("buffer overflow reading field 3")
			}
			msg.ErrorMsg = string(buf[idx : idx+int(length)])
			idx += int(length)

		case 5: // ip_addresses (IPAssignment, length-delimited)
			if wireType != 2 {
				return nil, fmt.Errorf("unexpected wire type for field 5: %d", wireType)
			}
			length, n := decodeVarint(buf[idx:])
			if n == 0 {
				return nil, errors.New("malformed length for field 5")
			}
			idx += n
			if idx+int(length) > limit {
				return nil, errors.New("buffer overflow reading field 5")
			}
			innerBuf := buf[idx : idx+int(length)]
			idx += int(length)

			// Parse inner IPAssignment fields
			innerIdx := 0
			for innerIdx < len(innerBuf) {
				innerTag, n := decodeVarint(innerBuf[innerIdx:])
				if n == 0 {
					break
				}
				innerIdx += n
				innerField := innerTag >> 3
				innerLength, n := decodeVarint(innerBuf[innerIdx:])
				if n == 0 {
					break
				}
				innerIdx += n
				if innerIdx+int(innerLength) > len(innerBuf) {
					break
				}
				if innerField == 1 {
					msg.IPv4Address = string(innerBuf[innerIdx : innerIdx+int(innerLength)])
				} else if innerField == 2 {
					msg.IPv6Address = string(innerBuf[innerIdx : innerIdx+int(innerLength)])
				}
				innerIdx += int(innerLength)
			}

		case 6: // batch (BatchIPPacket, length-delimited)
			if wireType != 2 {
				return nil, fmt.Errorf("unexpected wire type for field 6: %d", wireType)
			}
			length, n := decodeVarint(buf[idx:])
			if n == 0 {
				return nil, errors.New("malformed length for field 6")
			}
			idx += n
			if idx+int(length) > limit {
				return nil, errors.New("buffer overflow reading field 6")
			}
			innerBuf := buf[idx : idx+int(length)]
			idx += int(length)

			// Parse repeated packets inside BatchIPPacket
			innerIdx := 0
			for innerIdx < len(innerBuf) {
				innerTag, n := decodeVarint(innerBuf[innerIdx:])
				if n == 0 {
					break
				}
				innerIdx += n
				innerWire := innerTag & 0x07
				if innerWire != 2 {
					break
				}
				packetLen, n := decodeVarint(innerBuf[innerIdx:])
				if n == 0 {
					break
				}
				innerIdx += n
				if innerIdx+int(packetLen) > len(innerBuf) {
					break
				}
				packet := make([]byte, packetLen)
				copy(packet, innerBuf[innerIdx:innerIdx+int(packetLen)])
				msg.BatchPackets = append(msg.BatchPackets, packet)
				innerIdx += int(packetLen)
			}

		default:
			// Unknown/unsupported field: skip it safely
			if wireType == 0 {
				_, n := decodeVarint(buf[idx:])
				idx += n
			} else if wireType == 2 {
				length, n := decodeVarint(buf[idx:])
				idx += n + int(length)
			} else {
				idx++
			}
		}
	}

	return msg, nil
}

// Encode serializes an FPTNMessage into its protobuf wire format representation.
func (c *FPTNPacketCodec) Encode(msg *FPTNMessage) []byte {
	var out []byte

	// 1. protocol_version (tag = 1<<3 | 0 = 8)
	out = append(out, 0x08)
	out = append(out, encodeVarint(uint64(msg.Version))...)

	// 2. msg_type (tag = 2<<3 | 0 = 16)
	out = append(out, 0x10)
	out = append(out, encodeVarint(uint64(msg.Type))...)

	switch msg.Type {
	case FPTNMsgIPAssignment:
		// 5. ip_addresses (tag = 5<<3 | 2 = 42)
		var inner []byte
		if msg.IPv4Address != "" {
			// Field 1: address_ipv4 (tag = 1<<3 | 2 = 10)
			inner = append(inner, 0x0a)
			inner = append(inner, encodeVarint(uint64(len(msg.IPv4Address)))...)
			inner = append(inner, []byte(msg.IPv4Address)...)
		}
		if msg.IPv6Address != "" {
			// Field 2: address_ipv6 (tag = 2<<3 | 2 = 18)
			inner = append(inner, 0x12)
			inner = append(inner, encodeVarint(uint64(len(msg.IPv6Address)))...)
			inner = append(inner, []byte(msg.IPv6Address)...)
		}
		out = append(out, 0x2a)
		out = append(out, encodeVarint(uint64(len(inner)))...)
		out = append(out, inner...)

	case FPTNMsgBatchPacket:
		// 6. batch (tag = 6<<3 | 2 = 50)
		var inner []byte
		for _, packet := range msg.BatchPackets {
			// Field 1: packets (repeated bytes, tag = 1<<3 | 2 = 10)
			inner = append(inner, 0x0a)
			inner = append(inner, encodeVarint(uint64(len(packet)))...)
			inner = append(inner, packet...)
		}
		out = append(out, 0x32)
		out = append(out, encodeVarint(uint64(len(inner)))...)
		out = append(out, inner...)

	case FPTNMsgError:
		// 3. error (tag = 3<<3 | 2 = 26)
		out = append(out, 0x1a)
		out = append(out, encodeVarint(uint64(len(msg.ErrorMsg)))...)
		out = append(out, []byte(msg.ErrorMsg)...)
	}

	return out
}

func decodeVarint(buf []byte) (uint64, int) {
	var x uint64
	var s uint
	for i, b := range buf {
		if b < 0x80 {
			if i > 9 || (i == 9 && b > 1) {
				return 0, 0
			}
			return x | uint64(b)<<s, i + 1
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0
}

func encodeVarint(x uint64) []byte {
	var buf [10]byte
	var i int
	for x >= 0x80 {
		buf[i] = byte(x) | 0x80
		i++
		x >>= 7
	}
	buf[i] = byte(x)
	return buf[:i+1]
}
