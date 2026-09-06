package transport

import (
	"errors"
)

var (
	ErrEmptySourceGroup = errors.New("empty source group")
)

type PacketFecEncoder struct {
	GroupSize int
}

func NewPacketFecEncoder(groupSize int) *PacketFecEncoder {
	if groupSize <= 0 {
		groupSize = 4
	}
	return &PacketFecEncoder{
		GroupSize: groupSize,
	}
}

func (e *PacketFecEncoder) ComputeParity(sources [][]byte) ([]byte, error) {
	if len(sources) == 0 {
		return nil, ErrEmptySourceGroup
	}

	maxLen := 0
	for _, p := range sources {
		if len(p) > maxLen {
			maxLen = len(p)
		}
	}

	parity := make([]byte, maxLen)
	for _, p := range sources {
		for i := 0; i < len(p); i++ {
			parity[i] ^= p[i]
		}
	}

	return parity, nil
}

func RecoverSingleMissing(knownSources [][]byte, parity []byte, expectedLen int) []byte {
	recovered := make([]byte, len(parity))
	copy(recovered, parity)

	for _, p := range knownSources {
		for i := 0; i < len(p) && i < len(recovered); i++ {
			recovered[i] ^= p[i]
		}
	}

	if expectedLen < len(recovered) {
		return recovered[:expectedLen]
	}
	return recovered
}
