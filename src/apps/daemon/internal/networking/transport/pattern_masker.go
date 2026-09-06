package transport

import (
	"bytes"
)

type DpiPatternMasker struct {
	SplitOffset        int
	InsertNoiseRecord bool
}

func NewDpiPatternMasker(splitOffset int, insertNoise bool) *DpiPatternMasker {
	if splitOffset <= 0 {
		splitOffset = 5
	}
	return &DpiPatternMasker{
		SplitOffset:        splitOffset,
		InsertNoiseRecord: insertNoise,
	}
}

var FakeAlertHeader = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00}

func (m *DpiPatternMasker) FragmentPayload(payload []byte) [][]byte {
	if len(payload) <= m.SplitOffset {
		return [][]byte{payload}
	}

	var fragments [][]byte
	if m.InsertNoiseRecord && len(payload) >= 2 && payload[0] == 0x16 && payload[1] == 0x03 {
		fake := make([]byte, len(FakeAlertHeader))
		copy(fake, FakeAlertHeader)
		fragments = append(fragments, fake)
	}

	splitAt := m.SplitOffset
	if splitAt > len(payload)-1 {
		splitAt = len(payload) - 1
	}

	part1 := make([]byte, splitAt)
	copy(part1, payload[:splitAt])
	part2 := make([]byte, len(payload)-splitAt)
	copy(part2, payload[splitAt:])

	fragments = append(fragments, part1, part2)
	return fragments
}

func ReassemblePayload(fragments [][]byte) []byte {
	var buf bytes.Buffer
	for _, f := range fragments {
		if bytes.Equal(f, FakeAlertHeader) {
			continue
		}
		buf.Write(f)
	}
	return buf.Bytes()
}
