package transport

import (
	"bytes"
	"fmt"
)

// DesyncStrategy defines DPI evasion strategies.
type DesyncStrategy int

const (
	DesyncNone DesyncStrategy = iota
	DesyncSplit
	DesyncFakeTtl
	DesyncDisorder
)

// DesyncSegment represents a slice of TCP payload with injected TTL or order marker.
type DesyncSegment struct {
	TTL     uint8
	Payload []byte
	IsFake  bool
}

// PlanDesyncAttack splits data into evasion segments based on strategy and split offset.
func PlanDesyncAttack(strategy DesyncStrategy, splitOffset int, data []byte) ([]DesyncSegment, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	if splitOffset <= 0 || splitOffset >= len(data) {
		splitOffset = len(data) / 2
		if splitOffset == 0 {
			splitOffset = 1
		}
	}

	switch strategy {
	case DesyncSplit:
		return []DesyncSegment{
			{TTL: 64, Payload: data[:splitOffset], IsFake: false},
			{TTL: 64, Payload: data[splitOffset:], IsFake: false},
		}, nil

	case DesyncFakeTtl:
		// Fake packet with TTL 3 (dropped by censor before target)
		fake := bytes.Repeat([]byte{0x58}, splitOffset) // 'X' filler
		return []DesyncSegment{
			{TTL: 3, Payload: fake, IsFake: true},
			{TTL: 64, Payload: data[:splitOffset], IsFake: false},
			{TTL: 64, Payload: data[splitOffset:], IsFake: false},
		}, nil

	case DesyncDisorder:
		// Send second chunk first
		return []DesyncSegment{
			{TTL: 64, Payload: data[splitOffset:], IsFake: false},
			{TTL: 64, Payload: data[:splitOffset], IsFake: false},
		}, nil

	default:
		return []DesyncSegment{
			{TTL: 64, Payload: data, IsFake: false},
		}, nil
	}
}
