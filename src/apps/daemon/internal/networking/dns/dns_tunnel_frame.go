package dns

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type DnsTunnelFrame struct {
	SessionID uint16
	Sequence  uint16
	IsFinal   bool
	Payload   []byte
}

type DnsTunnelCodec struct{}

func NewDnsTunnelCodec() *DnsTunnelCodec {
	return &DnsTunnelCodec{}
}

func (c *DnsTunnelCodec) EncodeToQuery(frame *DnsTunnelFrame, domainSuffix string) string {
	raw := make([]byte, 5+len(frame.Payload))
	binary.BigEndian.PutUint16(raw[0:2], frame.SessionID)
	binary.BigEndian.PutUint16(raw[2:4], frame.Sequence)
	if frame.IsFinal {
		raw[4] = 1
	} else {
		raw[4] = 0
	}
	copy(raw[5:], frame.Payload)

	hexStr := hex.EncodeToString(raw)
	return fmt.Sprintf("%s.%s", hexStr, domainSuffix)
}

func (c *DnsTunnelCodec) DecodeFromQuery(query, domainSuffix string) (*DnsTunnelFrame, error) {
	if !strings.HasSuffix(query, domainSuffix) {
		return nil, errors.New("domain suffix mismatch")
	}
	trimmed := strings.TrimSuffix(query, domainSuffix)
	trimmed = strings.TrimSuffix(trimmed, ".")
	parts := strings.Split(trimmed, ".")
	if len(parts) == 0 {
		return nil, errors.New("empty label")
	}

	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	if len(raw) < 5 {
		return nil, errors.New("frame too short")
	}

	sess := binary.BigEndian.Uint16(raw[0:2])
	seq := binary.BigEndian.Uint16(raw[2:4])
	isFinal := raw[4] == 1
	payload := make([]byte, len(raw)-5)
	copy(payload, raw[5:])

	return &DnsTunnelFrame{
		SessionID: sess,
		Sequence:  seq,
		IsFinal:   isFinal,
		Payload:   payload,
	}, nil
}
