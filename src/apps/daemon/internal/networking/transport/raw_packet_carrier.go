package transport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	PaqetCarrierMagic = 0x50514554 // "PQET"
)

// RawCarrierPacket encapsulates encapsulated L3/L4 IP payloads.
type RawCarrierPacket struct {
	Sequence  uint32
	SessionID uint32
	Checksum  uint16
	Payload   []byte
}

// ComputeCarrierChecksum computes standard 16-bit one's complement sum.
func ComputeCarrierChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// EncodeCarrierPacket serializes packet with magic, headers, and computed checksum.
func EncodeCarrierPacket(seq, session uint32, payload []byte) []byte {
	csum := ComputeCarrierChecksum(payload)
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint32(PaqetCarrierMagic))
	_ = binary.Write(buf, binary.BigEndian, seq)
	_ = binary.Write(buf, binary.BigEndian, session)
	_ = binary.Write(buf, binary.BigEndian, csum)
	_ = binary.Write(buf, binary.BigEndian, uint16(len(payload)))
	buf.Write(payload)
	return buf.Bytes()
}

// DecodeCarrierPacket decodes and validates magic and checksum.
func DecodeCarrierPacket(r io.Reader) (*RawCarrierPacket, error) {
	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, err
	}
	if magic != PaqetCarrierMagic {
		return nil, fmt.Errorf("invalid paqet magic: 0x%x", magic)
	}

	var seq, session uint32
	if err := binary.Read(r, binary.BigEndian, &seq); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &session); err != nil {
		return nil, err
	}

	var csum, length uint16
	if err := binary.Read(r, binary.BigEndian, &csum); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	calculated := ComputeCarrierChecksum(payload)
	if calculated != csum {
		return nil, fmt.Errorf("checksum mismatch: expected 0x%04x, got 0x%04x", csum, calculated)
	}

	return &RawCarrierPacket{
		Sequence:  seq,
		SessionID: session,
		Checksum:  csum,
		Payload:   payload,
	}, nil
}
