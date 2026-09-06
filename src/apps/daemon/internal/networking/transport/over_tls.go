package transport

import (
	"encoding/binary"
	"errors"
)

const OverTlsMagic uint16 = 0x544F

type OverTlsFrameType byte

const (
	FrameData    OverTlsFrameType = 0x01
	FramePadding OverTlsFrameType = 0x02
	FramePing    OverTlsFrameType = 0x03
	FramePong    OverTlsFrameType = 0x04
)

type OverTlsCodec struct {
	MaxPadding byte
}

func NewOverTlsCodec(maxPadding byte) *OverTlsCodec {
	return &OverTlsCodec{MaxPadding: maxPadding}
}

func (c *OverTlsCodec) EncodeFrame(ft OverTlsFrameType, payload []byte, paddingLen byte) []byte {
	pLen := paddingLen
	if pLen > c.MaxPadding {
		pLen = c.MaxPadding
	}
	nLen := uint16(len(payload))
	total := 6 + len(payload) + int(pLen)
	buf := make([]byte, total)

	binary.BigEndian.PutUint16(buf[0:2], OverTlsMagic)
	buf[2] = byte(ft)
	buf[3] = pLen
	binary.BigEndian.PutUint16(buf[4:6], nLen)
	copy(buf[6:6+nLen], payload)

	for i := 0; i < int(pLen); i++ {
		buf[6+int(nLen)+i] = byte((i*37) ^ 0xA5)
	}
	return buf
}

func (c *OverTlsCodec) DecodeFrame(buf []byte) (OverTlsFrameType, []byte, int, error) {
	if len(buf) < 6 {
		return 0, nil, 0, errors.New("buffer too short")
	}
	magic := binary.BigEndian.Uint16(buf[0:2])
	if magic != OverTlsMagic {
		return 0, nil, 0, errors.New("invalid magic")
	}
	ft := OverTlsFrameType(buf[2])
	pLen := int(buf[3])
	nLen := int(binary.BigEndian.Uint16(buf[4:6]))
	total := 6 + nLen + pLen
	if len(buf) < total {
		return 0, nil, 0, errors.New("incomplete frame")
	}
	payload := make([]byte, nLen)
	copy(payload, buf[6:6+nLen])
	return ft, payload, total, nil
}
