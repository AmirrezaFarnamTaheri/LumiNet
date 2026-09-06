package transport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	ServerlessMagicHeader = 0x534c5353 // "SLSS"
)

// ServerlessFrame represents a multiplexed tunnel frame transported over edge HTTP/2.
type ServerlessFrame struct {
	StreamID uint32
	IsEOF    bool
	Payload  []byte
}

// EncodeServerlessFrame serializes a frame for HTTP/2 transmission.
func EncodeServerlessFrame(frame ServerlessFrame) []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, uint32(ServerlessMagicHeader))
	_ = binary.Write(buf, binary.BigEndian, frame.StreamID)
	var flag byte = 0
	if frame.IsEOF {
		flag = 1
	}
	buf.WriteByte(flag)
	_ = binary.Write(buf, binary.BigEndian, uint32(len(frame.Payload)))
	buf.Write(frame.Payload)
	return buf.Bytes()
}

// DecodeServerlessFrame deserializes a frame from an edge stream.
func DecodeServerlessFrame(r io.Reader) (*ServerlessFrame, error) {
	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, err
	}
	if magic != ServerlessMagicHeader {
		return nil, fmt.Errorf("invalid serverless magic: 0x%x", magic)
	}

	var streamID uint32
	if err := binary.Read(r, binary.BigEndian, &streamID); err != nil {
		return nil, err
	}

	flagBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, flagBuf); err != nil {
		return nil, err
	}
	isEOF := flagBuf[0] == 1

	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return &ServerlessFrame{
		StreamID: streamID,
		IsEOF:    isEOF,
		Payload:  payload,
	}, nil
}
