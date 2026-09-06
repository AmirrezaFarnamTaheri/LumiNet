package transport

import (
	"encoding/json"
	"errors"
)

type QuicTunnelMetrics struct {
	ConnectionState        QuicConnectionState `json:"connection_state"`
	TotalDatagramsSent     uint64              `json:"total_datagrams_sent"`
	TotalDatagramsReceived uint64              `json:"total_datagrams_received"`
	ActiveStreams          int                 `json:"active_streams"`
	EvasionActive          bool                `json:"evasion_active"`
}

type QuicEvasionTunnelCoordinator struct {
	multiplexer    *QuicStreamMultiplexer
	connection     *QuicConnectionController
	masquerader    *SniSegmentationMasquerader
	replaySession  *ReplayResistantTunnelSession
	destCID        []byte
	srcCID         []byte
	nextPacketNum  uint64
	totalSent      uint64
	totalRecv      uint64
	evasionActive  bool
	quicCodec      QuicPacketCodec
}

func NewQuicEvasionTunnelCoordinator(
	destCID, srcCID []byte,
	clientRandom, serverRandom []byte,
	evasionActive bool,
) *QuicEvasionTunnelCoordinator {
	replayCfg := DefaultReplayResistantConfig()
	replaySess := NewReplayResistantTunnelSession(replayCfg, clientRandom, serverRandom)

	conn := NewQuicConnectionController(65536)
	conn.SetState(ConnEstablished)

	return &QuicEvasionTunnelCoordinator{
		multiplexer:    NewQuicStreamMultiplexer(65536),
		connection:     conn,
		masquerader:    NewSniSegmentationMasquerader(StrategyMidSniSplit, 8, 32),
		replaySession:  replaySess,
		destCID:        destCID,
		srcCID:         srcCID,
		nextPacketNum:  1,
		totalSent:      0,
		totalRecv:      0,
		evasionActive:  evasionActive,
		quicCodec:      QuicPacketCodec{},
	}
}

func (q *QuicEvasionTunnelCoordinator) OpenTunnelStream() uint64 {
	return q.multiplexer.OpenStream(QuicClientBidi)
}

func (q *QuicEvasionTunnelCoordinator) PrepareOutboundDatagram(streamID uint64, appData []byte, timestampSecs int64) ([][]byte, error) {
	frame, err := q.multiplexer.WriteStreamData(streamID, appData, false)
	if err != nil {
		return nil, err
	}

	frameBytes, err := json.Marshal(frame)
	if err != nil {
		return nil, err
	}

	hdr := QuicPacketHeader{
		HeaderType:   QuicPkt1RttShort,
		Version:      0,
		DestCID:      q.destCID,
		SrcCID:       q.srcCID,
		PacketNumber: q.nextPacketNum,
	}
	quicPacket := q.quicCodec.EncodePacket(hdr, frameBytes)

	sealed := q.replaySession.SealPacket(q.nextPacketNum, timestampSecs, quicPacket)
	q.connection.OnPacketSent(q.nextPacketNum, len(sealed), timestampSecs*1000)

	q.nextPacketNum++
	q.totalSent++

	if q.evasionActive {
		return q.masquerader.SegmentStream(sealed, int64(q.nextPacketNum)), nil
	}
	return [][]byte{sealed}, nil
}

func (q *QuicEvasionTunnelCoordinator) ProcessInboundDatagram(sealedDatagram []byte, currentTimeSecs int64) (uint64, []byte, error) {
	seq, _, quicPacket, err := q.replaySession.OpenPacket(sealedDatagram, currentTimeSecs)
	if err != nil {
		return 0, nil, err
	}

	q.connection.OnAckReceived(seq, currentTimeSecs*1000)
	q.totalRecv++

	_, payload, err := q.quicCodec.DecodePacket(quicPacket, len(q.destCID))
	if err != nil {
		return 0, nil, err
	}

	var frame QuicStreamFrame
	if err := json.Unmarshal(payload, &frame); err != nil {
		return 0, nil, errors.New("malformed quic stream frame")
	}

	assembled, err := q.multiplexer.ReceiveStreamFrame(frame)
	if err != nil {
		return 0, nil, err
	}

	return frame.StreamID, assembled, nil
}

func (q *QuicEvasionTunnelCoordinator) GetTunnelMetrics() QuicTunnelMetrics {
	return QuicTunnelMetrics{
		ConnectionState:        q.connection.GetMetrics().State,
		TotalDatagramsSent:     q.totalSent,
		TotalDatagramsReceived: q.totalRecv,
		ActiveStreams:          1,
		EvasionActive:          q.evasionActive,
	}
}
