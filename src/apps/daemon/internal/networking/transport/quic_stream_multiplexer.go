package transport

import (
	"errors"
)

type QuicStreamType int

const (
	QuicClientBidi QuicStreamType = iota
	QuicServerBidi
	QuicClientUni
	QuicServerUni
)

type QuicStreamFrame struct {
	StreamID uint64 `json:"stream_id"`
	Offset   uint64 `json:"offset"`
	Fin      bool   `json:"fin"`
	Data     []byte `json:"data"`
}

type streamState struct {
	streamType     QuicStreamType
	sendOffset     uint64
	recvOffset     uint64
	maxSendCredit  uint64
	receivedChunks map[uint64][]byte
	finReceived    bool
	finOffset      uint64
}

type QuicStreamMultiplexer struct {
	streams             map[uint64]*streamState
	nextClientBidi      uint64
	nextClientUni       uint64
	defaultStreamWindow uint64
}

func NewQuicStreamMultiplexer(defaultWindow uint64) *QuicStreamMultiplexer {
	if defaultWindow < 1024 {
		defaultWindow = 1024
	}
	return &QuicStreamMultiplexer{
		streams:             make(map[uint64]*streamState),
		nextClientBidi:      0,
		nextClientUni:       2,
		defaultStreamWindow: defaultWindow,
	}
}

func (q *QuicStreamMultiplexer) OpenStream(streamType QuicStreamType) uint64 {
	var streamID uint64
	switch streamType {
	case QuicClientBidi:
		streamID = q.nextClientBidi
		q.nextClientBidi += 4
	case QuicClientUni:
		streamID = q.nextClientUni
		q.nextClientUni += 4
	case QuicServerBidi:
		streamID = 1
	case QuicServerUni:
		streamID = 3
	}

	q.streams[streamID] = &streamState{
		streamType:     streamType,
		sendOffset:     0,
		recvOffset:     0,
		maxSendCredit:  q.defaultStreamWindow,
		receivedChunks: make(map[uint64][]byte),
	}

	return streamID
}

func (q *QuicStreamMultiplexer) WriteStreamData(streamID uint64, data []byte, fin bool) (QuicStreamFrame, error) {
	stream, ok := q.streams[streamID]
	if !ok {
		return QuicStreamFrame{}, errors.New("stream not found")
	}

	length := uint64(len(data))
	if stream.sendOffset+length > stream.maxSendCredit {
		return QuicStreamFrame{}, errors.New("flow control window exceeded")
	}

	frame := QuicStreamFrame{
		StreamID: streamID,
		Offset:   stream.sendOffset,
		Fin:      fin,
		Data:     data,
	}

	stream.sendOffset += length
	return frame, nil
}

func (q *QuicStreamMultiplexer) ReceiveStreamFrame(frame QuicStreamFrame) ([]byte, error) {
	stream, ok := q.streams[frame.StreamID]
	if !ok {
		stream = &streamState{
			streamType:     QuicClientBidi,
			sendOffset:     0,
			recvOffset:     0,
			maxSendCredit:  q.defaultStreamWindow,
			receivedChunks: make(map[uint64][]byte),
		}
		q.streams[frame.StreamID] = stream
	}

	if frame.Fin {
		stream.finReceived = true
		stream.finOffset = frame.Offset + uint64(len(frame.Data))
	}

	stream.receivedChunks[frame.Offset] = frame.Data

	var assembled []byte
	for {
		chunk, exists := stream.receivedChunks[stream.recvOffset]
		if !exists {
			break
		}
		delete(stream.receivedChunks, stream.recvOffset)
		stream.recvOffset += uint64(len(chunk))
		assembled = append(assembled, chunk...)
	}

	return assembled, nil
}

func (q *QuicStreamMultiplexer) IsStreamClosed(streamID uint64) bool {
	if stream, ok := q.streams[streamID]; ok {
		if stream.finReceived && stream.recvOffset >= stream.finOffset {
			return true
		}
	}
	return false
}

func (q *QuicStreamMultiplexer) GrantCredit(streamID uint64, extra uint64) {
	if stream, ok := q.streams[streamID]; ok {
		stream.maxSendCredit += extra
	}
}
