package transport

import (
	"math"
)

type QuicConnectionState int

const (
	ConnIdle QuicConnectionState = iota
	ConnHandshaking
	ConnEstablished
	ConnClosing
	ConnClosed
)

type QuicConnectionMetrics struct {
	State           QuicConnectionState `json:"state"`
	SmoothedRttMs   uint32              `json:"smoothed_rtt_ms"`
	RttVarMs        uint32              `json:"rttvar_ms"`
	MinRttMs        uint32              `json:"min_rtt_ms"`
	CwndBytes       uint64              `json:"cwnd_bytes"`
	BytesInFlight   uint64              `json:"bytes_in_flight"`
	LostPacketCount uint64              `json:"lost_packet_count"`
}

type sentPacketRecord struct {
	packetNumber uint64
	sizeBytes    int
	timeSentMs   int64
}

type QuicConnectionController struct {
	state           QuicConnectionState
	smoothedRttMs   uint32
	rttVarMs        uint32
	minRttMs        uint32
	cwndBytes       uint64
	bytesInFlight   uint64
	lostPacketCount uint64
	ssthreshBytes   uint64
	sentPackets     map[uint64]sentPacketRecord
}

func NewQuicConnectionController(initialWindowBytes uint64) *QuicConnectionController {
	if initialWindowBytes < 14720 {
		initialWindowBytes = 14720
	}
	return &QuicConnectionController{
		state:         ConnIdle,
		smoothedRttMs: 100,
		rttVarMs:      50,
		minRttMs:      math.MaxUint32,
		cwndBytes:     initialWindowBytes,
		ssthreshBytes: math.MaxUint64,
		sentPackets:   make(map[uint64]sentPacketRecord),
	}
}

func (q *QuicConnectionController) SetState(state QuicConnectionState) {
	q.state = state
}

func (q *QuicConnectionController) CanSend(size int) bool {
	return q.state == ConnEstablished && (q.bytesInFlight+uint64(size) <= q.cwndBytes)
}

func (q *QuicConnectionController) OnPacketSent(pktNum uint64, size int, timeSentMs int64) {
	q.bytesInFlight += uint64(size)
	q.sentPackets[pktNum] = sentPacketRecord{
		packetNumber: pktNum,
		sizeBytes:    size,
		timeSentMs:   timeSentMs,
	}
}

func (q *QuicConnectionController) OnAckReceived(pktNum uint64, nowMs int64) {
	rec, ok := q.sentPackets[pktNum]
	if !ok {
		return
	}
	delete(q.sentPackets, pktNum)

	if q.bytesInFlight >= uint64(rec.sizeBytes) {
		q.bytesInFlight -= uint64(rec.sizeBytes)
	} else {
		q.bytesInFlight = 0
	}

	if nowMs >= rec.timeSentMs {
		sampleRtt := uint32(nowMs - rec.timeSentMs)
		q.updateRtt(sampleRtt)
	}

	if q.cwndBytes < q.ssthreshBytes {
		q.cwndBytes += uint64(rec.sizeBytes)
	} else {
		increment := (1472 * 1472) / q.cwndBytes
		if increment < 1 {
			increment = 1
		}
		q.cwndBytes += increment
	}
}

func (q *QuicConnectionController) OnPacketLoss(pktNum uint64) {
	rec, ok := q.sentPackets[pktNum]
	if !ok {
		return
	}
	delete(q.sentPackets, pktNum)

	if q.bytesInFlight >= uint64(rec.sizeBytes) {
		q.bytesInFlight -= uint64(rec.sizeBytes)
	} else {
		q.bytesInFlight = 0
	}
	q.lostPacketCount++

	q.ssthreshBytes = q.cwndBytes / 2
	if q.ssthreshBytes < 14720 {
		q.ssthreshBytes = 14720
	}
	q.cwndBytes = q.ssthreshBytes
}

func (q *QuicConnectionController) CalculatePtoMs() uint32 {
	fourRttVar := 4 * q.rttVarMs
	if fourRttVar < 10 {
		fourRttVar = 10
	}
	return q.smoothedRttMs + fourRttVar
}

func (q *QuicConnectionController) GetMetrics() QuicConnectionMetrics {
	minRtt := q.minRttMs
	if minRtt == math.MaxUint32 {
		minRtt = 0
	}
	return QuicConnectionMetrics{
		State:           q.state,
		SmoothedRttMs:   q.smoothedRttMs,
		RttVarMs:        q.rttVarMs,
		MinRttMs:        minRtt,
		CwndBytes:       q.cwndBytes,
		BytesInFlight:   q.bytesInFlight,
		LostPacketCount: q.lostPacketCount,
	}
}

func (q *QuicConnectionController) updateRtt(sample uint32) {
	if q.minRttMs == math.MaxUint32 {
		q.minRttMs = sample
		q.smoothedRttMs = sample
		q.rttVarMs = sample / 2
	} else {
		if sample < q.minRttMs {
			q.minRttMs = sample
		}
		diff := uint32(0)
		if sample > q.smoothedRttMs {
			diff = sample - q.smoothedRttMs
		} else {
			diff = q.smoothedRttMs - sample
		}
		q.rttVarMs = (3*q.rttVarMs + diff) / 4
		q.smoothedRttMs = (7*q.smoothedRttMs + sample) / 8
	}
}
