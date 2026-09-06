package nat

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	defaultDefragMaxAge   = 30 * time.Second
	defaultDefragMaxFlows = 256
	maxIPv4PacketBytes    = 65535
	fragmentBitmapBytes   = (maxIPv4PacketBytes + 7) / 8
)

// IPFlow defines a unique packet stream identifier for defragmentation.
type IPFlow struct {
	SrcIP    string
	DstIP    string
	Protocol byte
	ID       uint16
}

type fragmentList struct {
	data        []byte
	received    []byte
	receivedCnt int
	finalLen    int
	maxSeen     int
	header      []byte
	createdAt   time.Time
	updatedAt   time.Time
}

// IPv4Defragmenter handles bounded, conflict-aware reassembly of fragmented
// IPv4 packets. State is capped by flow count, datagram size, and age.
type IPv4Defragmenter struct {
	mu       sync.Mutex
	flows    map[IPFlow]*fragmentList
	maxAge   time.Duration
	maxFlows int
}

// NewIPv4Defragmenter creates a new IPv4 packet defragmenter.
func NewIPv4Defragmenter() *IPv4Defragmenter {
	return &IPv4Defragmenter{
		flows:    make(map[IPFlow]*fragmentList),
		maxAge:   defaultDefragMaxAge,
		maxFlows: defaultDefragMaxFlows,
	}
}

var (
	// ErrIncompleteFragment is returned when a packet is fragmented and more pieces are needed.
	ErrIncompleteFragment = errors.New("tcpip: fragmented packet is incomplete")
	// ErrConflictingFragment is returned when overlapping fragments disagree or
	// imply different final datagram lengths. The ambiguous flow is discarded.
	ErrConflictingFragment = errors.New("tcpip: conflicting IPv4 fragments")
	// ErrInvalidFragment is returned for structurally impossible fragments.
	ErrInvalidFragment = errors.New("tcpip: invalid IPv4 fragment")
)

// DefragIPv4 processes an incoming IPv4 packet. Non-fragmented packets pass
// through unchanged. Fragmented datagrams are reassembled by their byte
// offsets, tolerate byte-identical duplicate overlap, and reject ambiguous
// conflicting overlap rather than letting arrival order choose bytes.
func (d *IPv4Defragmenter) DefragIPv4(raw []byte) ([]byte, error) {
	if len(raw) < IPv4HeaderSize {
		return raw, nil
	}

	ip := IPv4Packet(raw)
	if !ip.Valid() {
		return raw, nil
	}

	more := (ip.Flags() & FlagMoreFragment) != 0
	offset := int(ip.FragmentOffset())
	if !more && offset == 0 {
		return raw, nil
	}

	headerLen := int(ip.HeaderLen())
	payload := ip.Payload()
	if more && len(payload)%8 != 0 {
		return nil, fmt.Errorf("%w: non-final payload length %d is not a multiple of 8", ErrInvalidFragment, len(payload))
	}
	end := offset + len(payload)
	// Fragment offsets are relative to the datagram payload, while IPv4 options
	// may make non-zero fragments use a different header length from fragment
	// zero. Admit against the protocol-wide maximum here; once fragment zero is
	// known, the final assembly check applies its authoritative header length.
	maxPayload := maxIPv4PacketBytes - IPv4HeaderSize
	if offset < 0 || end < offset || end > maxPayload {
		return nil, fmt.Errorf("%w: fragment range %d..%d exceeds IPv4 payload limit %d", ErrInvalidFragment, offset, end, maxPayload)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	d.cleanupStaleAt(now)

	flow := IPFlow{
		SrcIP:    ip.SourceIP().String(),
		DstIP:    ip.DestinationIP().String(),
		Protocol: ip.Protocol(),
		ID:       ip.Identification(),
	}

	list, exists := d.flows[flow]
	if !exists {
		if d.maxFlows <= 0 {
			return nil, fmt.Errorf("%w: defragmenter flow capacity disabled", ErrInvalidFragment)
		}
		if len(d.flows) >= d.maxFlows {
			d.evictOldest()
		}
		list = &fragmentList{
			received:  make([]byte, fragmentBitmapBytes),
			finalLen:  -1,
			createdAt: now,
			updatedAt: now,
		}
		d.flows[flow] = list
	}
	list.updatedAt = now

	if offset == 0 && list.header == nil {
		list.header = append([]byte(nil), raw[:headerLen]...)
	}
	if !more {
		if list.finalLen >= 0 && list.finalLen != end {
			delete(d.flows, flow)
			return nil, fmt.Errorf("%w: final lengths %d and %d disagree", ErrConflictingFragment, list.finalLen, end)
		}
		if list.maxSeen > end {
			delete(d.flows, flow)
			return nil, fmt.Errorf("%w: received bytes beyond declared final length %d", ErrConflictingFragment, end)
		}
		list.finalLen = end
	}
	if list.finalLen >= 0 && end > list.finalLen {
		delete(d.flows, flow)
		return nil, fmt.Errorf("%w: fragment ends at %d beyond final length %d", ErrConflictingFragment, end, list.finalLen)
	}

	if end > len(list.data) {
		grown := make([]byte, end)
		copy(grown, list.data)
		list.data = grown
	}
	for i, value := range payload {
		pos := offset + i
		if bitmapHas(list.received, pos) {
			if list.data[pos] != value {
				delete(d.flows, flow)
				return nil, fmt.Errorf("%w: byte %d differs across overlapping fragments", ErrConflictingFragment, pos)
			}
			continue
		}
		list.data[pos] = value
		bitmapSet(list.received, pos)
		list.receivedCnt++
	}
	if end > list.maxSeen {
		list.maxSeen = end
	}

	if list.finalLen < 0 || list.header == nil || list.receivedCnt < list.finalLen || !bitmapRangeComplete(list.received, list.finalLen) {
		return nil, ErrIncompleteFragment
	}

	headerLen = len(list.header)
	if headerLen < IPv4HeaderSize || headerLen+list.finalLen > maxIPv4PacketBytes {
		delete(d.flows, flow)
		return nil, fmt.Errorf("%w: reassembled packet length is invalid", ErrInvalidFragment)
	}
	newPacket := make([]byte, headerLen+list.finalLen)
	copy(newPacket[:headerLen], list.header)
	copy(newPacket[headerLen:], list.data[:list.finalLen])
	delete(d.flows, flow)

	newIP := IPv4Packet(newPacket)
	newIP.SetTotalLength(uint16(len(newPacket)))
	newIP.SetFlags(0)
	newIP.SetFragmentOffset(0)
	newIP.ResetChecksum()
	return newPacket, nil
}

func bitmapHas(bitmap []byte, position int) bool {
	return bitmap[position>>3]&(1<<uint(position&7)) != 0
}

func bitmapSet(bitmap []byte, position int) {
	bitmap[position>>3] |= 1 << uint(position&7)
}

func bitmapRangeComplete(bitmap []byte, length int) bool {
	for position := 0; position < length; position++ {
		if !bitmapHas(bitmap, position) {
			return false
		}
	}
	return true
}

func (d *IPv4Defragmenter) cleanupStale() {
	d.cleanupStaleAt(time.Now())
}

func (d *IPv4Defragmenter) cleanupStaleAt(now time.Time) {
	for key, value := range d.flows {
		if now.Sub(value.updatedAt) > d.maxAge {
			delete(d.flows, key)
		}
	}
}

func (d *IPv4Defragmenter) evictOldest() {
	var oldestKey IPFlow
	var oldestAt time.Time
	found := false
	for key, value := range d.flows {
		if !found || value.updatedAt.Before(oldestAt) {
			oldestKey = key
			oldestAt = value.updatedAt
			found = true
		}
	}
	if found {
		delete(d.flows, oldestKey)
	}
}
