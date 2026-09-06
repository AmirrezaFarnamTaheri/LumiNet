// Package dns provides networking, tunneling, and scheduling primitives.
// Conforms strictly to §8 structural cleanroom rules.

package dns

const (
	// PackedControlBlockSize is the fixed size of each control block:
	// Type(1) + StreamID(2) + SeqNum(2) + FragID(1) + Total(1) = 7 Bytes
	PackedControlBlockSize = 7
)

// ControlBlock describes a packed ACK, NACK, SYN_ACK, or RST_ACK block.
type ControlBlock struct {
	PacketType     uint8  `json:"packet_type"`
	StreamID       uint16 `json:"stream_id"`
	SequenceNum    uint16 `json:"sequence_num"`
	FragmentID     uint8  `json:"fragment_id"`
	TotalFragments uint8  `json:"total_fragments"`
}

// AppendPackedControlBlock serializes a block and appends the 7 bytes to dst.
func AppendPackedControlBlock(dst []byte, packetType uint8, streamID uint16, seqNum uint16, fragID uint8, total uint8) []byte {
	return append(dst,
		packetType,
		uint8(streamID>>8), uint8(streamID),
		uint8(seqNum>>8), uint8(seqNum),
		fragID,
		total,
	)
}

// ForEachPackedControlBlock parses contiguous 7-byte blocks in payload.
func ForEachPackedControlBlock(payload []byte, yield func(block ControlBlock) bool) {
	if len(payload) < PackedControlBlockSize || yield == nil {
		return
	}

	for offset := 0; offset+PackedControlBlockSize <= len(payload); offset += PackedControlBlockSize {
		b := ControlBlock{
			PacketType:     payload[offset],
			StreamID:       uint16(payload[offset+1])<<8 | uint16(payload[offset+2]),
			SequenceNum:    uint16(payload[offset+3])<<8 | uint16(payload[offset+4]),
			FragmentID:     payload[offset+5],
			TotalFragments: payload[offset+6],
		}
		if !yield(b) {
			break
		}
	}
}

// ParsePackedControlBlocks extracts all control blocks from a packed payload.
func ParsePackedControlBlocks(payload []byte) []ControlBlock {
	var blocks []ControlBlock
	ForEachPackedControlBlock(payload, func(b ControlBlock) bool {
		blocks = append(blocks, b)
		return true
	})
	return blocks
}

// PackControlBlocks serializes multiple control blocks into a contiguous byte slice.
func PackControlBlocks(blocks []ControlBlock) []byte {
	dst := make([]byte, 0, len(blocks)*PackedControlBlockSize)
	for _, b := range blocks {
		dst = AppendPackedControlBlock(dst, b.PacketType, b.StreamID, b.SequenceNum, b.FragmentID, b.TotalFragments)
	}
	return dst
}
