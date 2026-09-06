package transport

import (
	"encoding/binary"
	"errors"
)

type QuicHeaderType int

const (
	QuicPktInitial QuicHeaderType = iota
	QuicPktZeroRtt
	QuicPktHandshake
	QuicPktRetry
	QuicPkt1RttShort
)

type QuicPacketHeader struct {
	HeaderType   QuicHeaderType `json:"header_type"`
	Version      uint32         `json:"version"`
	DestCID      []byte         `json:"dest_cid"`
	SrcCID       []byte         `json:"src_cid"`
	PacketNumber uint64         `json:"packet_number"`
}

type QuicPacketCodec struct{}

func (q *QuicPacketCodec) EncodeVarint(value uint64) []byte {
	if value < (1 << 6) {
		return []byte{byte(value)}
	} else if value < (1 << 14) {
		return []byte{0x40 | byte(value>>8), byte(value & 0xff)}
	} else if value < (1 << 30) {
		return []byte{
			0x80 | byte(value>>24),
			byte((value >> 16) & 0xff),
			byte((value >> 8) & 0xff),
			byte(value & 0xff),
		}
	} else {
		out := []byte{0xc0 | byte(value>>56)}
		for i := 6; i >= 0; i-- {
			out = append(out, byte((value>>(i*8))&0xff))
		}
		return out
	}
}

func (q *QuicPacketCodec) DecodeVarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("empty varint input")
	}

	prefix := data[0] >> 6
	switch prefix {
	case 0:
		return uint64(data[0]), 1, nil
	case 1:
		if len(data) < 2 {
			return 0, 0, errors.New("varint truncated at 2 bytes")
		}
		val := (uint64(data[0]&0x3f) << 8) | uint64(data[1])
		return val, 2, nil
	case 2:
		if len(data) < 4 {
			return 0, 0, errors.New("varint truncated at 4 bytes")
		}
		val := (uint64(data[0]&0x3f) << 24) |
			(uint64(data[1]) << 16) |
			(uint64(data[2]) << 8) |
			uint64(data[3])
		return val, 4, nil
	case 3:
		if len(data) < 8 {
			return 0, 0, errors.New("varint truncated at 8 bytes")
		}
		val := uint64(data[0]&0x3f) << 56
		for i := 1; i < 8; i++ {
			val |= uint64(data[i]) << ((7 - i) * 8)
		}
		return val, 8, nil
	}
	return 0, 0, errors.New("invalid varint prefix")
}

func (q *QuicPacketCodec) EncodePacket(header QuicPacketHeader, payload []byte) []byte {
	var out []byte

	if header.HeaderType == QuicPkt1RttShort {
		// Short header: Form bit 0, Fixed bit 1
		firstByte := byte(0x40 | 0x01)
		out = append(out, firstByte)
		out = append(out, header.DestCID...)
		pnBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(pnBuf, uint16(header.PacketNumber))
		out = append(out, pnBuf...)
		out = append(out, payload...)
		return out
	}

	// Long header
	typeBits := byte(0)
	switch header.HeaderType {
	case QuicPktInitial:
		typeBits = 0x00
	case QuicPktZeroRtt:
		typeBits = 0x10
	case QuicPktHandshake:
		typeBits = 0x20
	case QuicPktRetry:
		typeBits = 0x30
	}

	firstByte := byte(0x80 | 0x40 | typeBits)
	out = append(out, firstByte)

	verBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(verBuf, header.Version)
	out = append(out, verBuf...)

	out = append(out, byte(len(header.DestCID)))
	out = append(out, header.DestCID...)

	out = append(out, byte(len(header.SrcCID)))
	out = append(out, header.SrcCID...)

	pnBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pnBuf, uint16(header.PacketNumber))

	lenVarint := q.EncodeVarint(uint64(len(pnBuf) + len(payload)))
	out = append(out, lenVarint...)

	out = append(out, pnBuf...)
	out = append(out, payload...)
	return out
}

func (q *QuicPacketCodec) DecodePacket(data []byte, destCidLen int) (QuicPacketHeader, []byte, error) {
	if len(data) == 0 {
		return QuicPacketHeader{}, nil, errors.New("empty packet")
	}

	firstByte := data[0]
	isLong := (firstByte & 0x80) != 0

	if isLong {
		if len(data) < 7 {
			return QuicPacketHeader{}, nil, errors.New("long header truncated")
		}

		typeBits := (firstByte & 0x30) >> 4
		hType := QuicPktInitial
		switch typeBits {
		case 0x00:
			hType = QuicPktInitial
		case 0x01:
			hType = QuicPktZeroRtt
		case 0x02:
			hType = QuicPktHandshake
		case 0x03:
			hType = QuicPktRetry
		}

		version := binary.BigEndian.Uint32(data[1:5])
		offset := 5

		dcidLen := int(data[offset])
		offset++
		if offset+dcidLen > len(data) {
			return QuicPacketHeader{}, nil, errors.New("dcid truncated")
		}
		dcid := make([]byte, dcidLen)
		copy(dcid, data[offset:offset+dcidLen])
		offset += dcidLen

		if offset >= len(data) {
			return QuicPacketHeader{}, nil, errors.New("scid len truncated")
		}
		scidLen := int(data[offset])
		offset++
		if offset+scidLen > len(data) {
			return QuicPacketHeader{}, nil, errors.New("scid truncated")
		}
		scid := make([]byte, scidLen)
		copy(scid, data[offset:offset+scidLen])
		offset += scidLen

		payloadLen, vlen, err := q.DecodeVarint(data[offset:])
		if err != nil {
			return QuicPacketHeader{}, nil, err
		}
		offset += vlen

		if offset+2 > len(data) {
			return QuicPacketHeader{}, nil, errors.New("pn truncated")
		}
		pn := uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		payloadSize := int(payloadLen) - 2
		if payloadSize < 0 || offset+payloadSize > len(data) {
			return QuicPacketHeader{}, nil, errors.New("payload truncated")
		}
		payload := data[offset : offset+payloadSize]

		return QuicPacketHeader{
			HeaderType:   hType,
			Version:      version,
			DestCID:      dcid,
			SrcCID:       scid,
			PacketNumber: pn,
		}, payload, nil
	}

	// Short header
	offset := 1
	if offset+destCidLen+2 > len(data) {
		return QuicPacketHeader{}, nil, errors.New("short header truncated")
	}

	dcid := make([]byte, destCidLen)
	copy(dcid, data[offset:offset+destCidLen])
	offset += destCidLen

	pn := uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	payload := data[offset:]
	return QuicPacketHeader{
		HeaderType:   QuicPkt1RttShort,
		Version:      0,
		DestCID:      dcid,
		SrcCID:       nil,
		PacketNumber: pn,
	}, payload, nil
}
