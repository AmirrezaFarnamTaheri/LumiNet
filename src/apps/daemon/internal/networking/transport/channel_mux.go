package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

type ChannelOpcode uint8

const (
	OpChannelOpen  ChannelOpcode = 1
	OpChannelData  ChannelOpcode = 2
	OpChannelClose ChannelOpcode = 3
	OpChannelAck   ChannelOpcode = 4
)

type ChannelMuxFrame struct {
	ChannelID uint32
	Opcode    ChannelOpcode
	Payload   []byte
}

func (f *ChannelMuxFrame) Encode(w io.Writer) error {
	buf := make([]byte, 4+1+2)
	binary.BigEndian.PutUint32(buf[0:4], f.ChannelID)
	buf[4] = byte(f.Opcode)
	binary.BigEndian.PutUint16(buf[5:7], uint16(len(f.Payload)))
	if _, err := w.Write(buf); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		_, err := w.Write(f.Payload)
		return err
	}
	return nil
}

func DecodeChannelMuxFrame(r io.Reader) (*ChannelMuxFrame, error) {
	buf := make([]byte, 7)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	cid := binary.BigEndian.Uint32(buf[0:4])
	op := ChannelOpcode(buf[4])
	length := binary.BigEndian.Uint16(buf[5:7])

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}
	return &ChannelMuxFrame{
		ChannelID: cid,
		Opcode:    op,
		Payload:   payload,
	}, nil
}

type ChannelSession struct {
	ID        uint32
	InboundCh chan []byte
	Closed    bool
}

type TransparentChannelMux struct {
	mu       sync.Mutex
	channels map[uint32]*ChannelSession
	nextID   uint32
}

func NewTransparentChannelMux() *TransparentChannelMux {
	return &TransparentChannelMux{
		channels: make(map[uint32]*ChannelSession),
		nextID:   1,
	}
}

func (m *TransparentChannelMux) OpenChannel() *ChannelSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	cid := m.nextID
	m.nextID++
	session := &ChannelSession{
		ID:        cid,
		InboundCh: make(chan []byte, 32),
		Closed:    false,
	}
	m.channels[cid] = session
	return session
}

func (m *TransparentChannelMux) CloseChannel(cid uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ch, exists := m.channels[cid]; exists {
		if !ch.Closed {
			ch.Closed = true
			close(ch.InboundCh)
		}
		delete(m.channels, cid)
	}
}

func (m *TransparentChannelMux) RoutePayload(cid uint32, payload []byte) error {
	m.mu.Lock()
	ch, exists := m.channels[cid]
	m.mu.Unlock()
	if !exists || ch.Closed {
		return errors.New("channel not found or closed")
	}
	select {
	case ch.InboundCh <- payload:
		return nil
	default:
		return errors.New("channel buffer full")
	}
}
