package transport

import (
	"encoding/binary"
	"math/rand"
)

type SniSegmentationStrategy int

const (
	StrategySniBorderSplit SniSegmentationStrategy = iota
	StrategyMidSniSplit
	StrategyRandomSplit
)

type SniSegmentationMasquerader struct {
	strategy     SniSegmentationStrategy
	minChunkSize int
	maxChunkSize int
}

func NewSniSegmentationMasquerader(strategy SniSegmentationStrategy, minChunk, maxChunk int) *SniSegmentationMasquerader {
	if minChunk < 2 {
		minChunk = 2
	}
	if maxChunk <= minChunk {
		maxChunk = minChunk + 1
	}
	return &SniSegmentationMasquerader{
		strategy:     strategy,
		minChunkSize: minChunk,
		maxChunkSize: maxChunk,
	}
}

func (s *SniSegmentationMasquerader) ExtractSNI(data []byte) (string, int, int, bool) {
	if len(data) < 43 || data[0] != 0x16 {
		return "", 0, 0, false
	}

	idx := 43
	if idx >= len(data) {
		return "", 0, 0, false
	}

	sessionIdLen := int(data[idx])
	idx += 1 + sessionIdLen
	if idx+2 >= len(data) {
		return "", 0, 0, false
	}

	cipherLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
	idx += 2 + cipherLen
	if idx+1 >= len(data) {
		return "", 0, 0, false
	}

	compLen := int(data[idx])
	idx += 1 + compLen
	if idx+2 >= len(data) {
		return "", 0, 0, false
	}

	extLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
	idx += 2
	extEnd := idx + extLen
	if extEnd > len(data) {
		extEnd = len(data)
	}

	for idx+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[idx : idx+2])
		extSize := int(binary.BigEndian.Uint16(data[idx+2 : idx+4]))
		idx += 4

		if extType == 0 && idx+extSize <= extEnd && extSize >= 5 {
			sniNameLen := int(binary.BigEndian.Uint16(data[idx+3 : idx+5]))
			sniStart := idx + 5
			sniEnd := sniStart + sniNameLen
			if sniEnd <= idx+extSize {
				sni := string(data[sniStart:sniEnd])
				return sni, sniStart, sniEnd, true
			}
		}
		idx += extSize
	}

	return "", 0, 0, false
}

func (s *SniSegmentationMasquerader) SegmentStream(data []byte, seed int64) [][]byte {
	if len(data) == 0 {
		return nil
	}

	if _, start, end, ok := s.ExtractSNI(data); ok {
		switch s.strategy {
		case StrategySniBorderSplit:
			var chunks [][]byte
			if start > 0 {
				chunks = append(chunks, data[:start])
			}
			chunks = append(chunks, data[start:end])
			if end < len(data) {
				chunks = append(chunks, data[end:])
			}
			return chunks
		case StrategyMidSniSplit:
			mid := start + (end-start)/2
			return [][]byte{data[:mid], data[mid:]}
		case StrategyRandomSplit:
			// fallthrough
		}
	}

	rng := rand.New(rand.NewSource(seed))
	var chunks [][]byte
	curr := 0

	for curr < len(data) {
		rem := len(data) - curr
		step := rem
		if rem > s.minChunkSize {
			rangeSpan := s.maxChunkSize - s.minChunkSize
			if rangeSpan < 1 {
				rangeSpan = 1
			}
			step = s.minChunkSize + (rng.Int() % rangeSpan)
			if step > rem {
				step = rem
			}
		}
		chunks = append(chunks, data[curr:curr+step])
		curr += step
	}

	return chunks
}
