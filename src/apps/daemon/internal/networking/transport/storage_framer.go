package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var (
	ErrStorageFrameHeaderTooShort = errors.New("storage frame header too short")
	ErrStorageFrameMagicMismatch   = errors.New("storage frame magic mismatch")
	ErrStorageFrameChecksumMismatch = errors.New("storage frame checksum mismatch")
	ErrStorageFrameDataTruncated   = errors.New("storage frame data truncated")
)

var StorageChunkMagic = []byte{0x53, 0x4B, 0x52, 0x4B} // "SKRK"

type CovertChunk struct {
	StreamID uint32
	Sequence uint64
	IsFin    bool
	Payload  []byte
}

type CovertStorageFramer struct{}

func (f *CovertStorageFramer) FrameChunk(chunk *CovertChunk) []byte {
	out := make([]byte, 22+len(chunk.Payload))
	copy(out[0:4], StorageChunkMagic)
	binary.BigEndian.PutUint32(out[4:8], chunk.StreamID)
	binary.BigEndian.PutUint64(out[8:16], chunk.Sequence)
	if chunk.IsFin {
		out[16] = 0x01
	} else {
		out[16] = 0x00
	}
	binary.BigEndian.PutUint32(out[17:21], uint32(len(chunk.Payload)))
	out[21] = computeCrc8(chunk.Payload)
	copy(out[22:], chunk.Payload)
	return out
}

func (f *CovertStorageFramer) UnframeChunk(buf []byte) (*CovertChunk, int, error) {
	if len(buf) < 22 {
		return nil, 0, ErrStorageFrameHeaderTooShort
	}

	if !bytes.Equal(buf[0:4], StorageChunkMagic) {
		return nil, 0, ErrStorageFrameMagicMismatch
	}

	streamID := binary.BigEndian.Uint32(buf[4:8])
	seq := binary.BigEndian.Uint64(buf[8:16])
	isFin := (buf[16] & 0x01) != 0
	payloadLen := int(binary.BigEndian.Uint32(buf[17:21]))
	expectedCrc := buf[21]

	totalSize := 22 + payloadLen
	if len(buf) < totalSize {
		return nil, 0, ErrStorageFrameDataTruncated
	}

	payload := make([]byte, payloadLen)
	copy(payload, buf[22:totalSize])

	if computeCrc8(payload) != expectedCrc {
		return nil, 0, ErrStorageFrameChecksumMismatch
	}

	return &CovertChunk{
		StreamID: streamID,
		Sequence: seq,
		IsFin:    isFin,
		Payload:  payload,
	}, totalSize, nil
}

func computeCrc8(data []byte) byte {
	var crc byte = 0x00
	for _, b := range data {
		crc ^= b
		for i := 0; i < 8; i++ {
			if (crc & 0x80) != 0 {
				crc = (crc << 1) ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
