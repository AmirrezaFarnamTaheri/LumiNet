package transport

import (
	"encoding/binary"
	"sync"
)

type NoisePattern struct {
	MinPadding  int
	MaxPadding  int
	HeaderMagic []byte
}

func DefaultNoisePattern() NoisePattern {
	return NoisePattern{
		MinPadding:  8,
		MaxPadding:  64,
		HeaderMagic: []byte{0x17, 0x03, 0x03}, // TLS Application Data mimic
	}
}

type NoisePacketInjector struct {
	mu      sync.Mutex
	pattern NoisePattern
}

func NewNoisePacketInjector(pattern NoisePattern) *NoisePacketInjector {
	return &NoisePacketInjector{pattern: pattern}
}

func (inj *NoisePacketInjector) SynthesizeNoiseFrame(seed uint64) []byte {
	inj.mu.Lock()
	defer inj.mu.Unlock()

	span := inj.pattern.MaxPadding - inj.pattern.MinPadding
	if span <= 0 {
		span = 1
	}
	padLen := inj.pattern.MinPadding + int(seed%uint64(span))
	frame := make([]byte, len(inj.pattern.HeaderMagic)+2+padLen)
	copy(frame[0:len(inj.pattern.HeaderMagic)], inj.pattern.HeaderMagic)

	binary.BigEndian.PutUint16(frame[len(inj.pattern.HeaderMagic):len(inj.pattern.HeaderMagic)+2], uint16(padLen))

	cur := seed
	offset := len(inj.pattern.HeaderMagic) + 2
	for i := 0; i < padLen; i++ {
		cur = cur*6364136223846793005 + 1
		frame[offset+i] = byte(cur >> 32)
	}
	return frame
}
