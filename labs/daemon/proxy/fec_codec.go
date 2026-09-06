package proxy

import (
	"fmt"
)

// FECCodec handles Reed-Solomon style packet protection.
type FECCodec struct {
	dataShards   int
	parityShards int
}

func NewFECCodec(data, parity int) *FECCodec {
	return &FECCodec{
		dataShards:   data,
		parityShards: parity,
	}
}

// Encode generates parity packets from a list of data shards.
func (c *FECCodec) Encode(shards [][]byte) ([][]byte, error) {
	if len(shards) != c.dataShards {
		return nil, fmt.Errorf("invalid number of data shards: %d", len(shards))
	}

	parity := make([][]byte, c.parityShards)
	for i := 0; i < c.parityShards; i++ {
		parity[i] = make([]byte, len(shards[0]))
		for _, shard := range shards {
			for idx := range shard {
				parity[i][idx] ^= shard[idx]
			}
		}
	}
	return parity, nil
}

// Decode recovers a missing shard in a group by XORing all other shards against the parity shard.
func (c *FECCodec) Decode(shards [][]byte, missingIdx int) ([]byte, error) {
	if len(shards) != c.dataShards+c.parityShards {
		return nil, fmt.Errorf("invalid number of total shards: %d", len(shards))
	}
	if missingIdx < 0 || missingIdx >= c.dataShards {
		return nil, fmt.Errorf("invalid missing shard index: %d", missingIdx)
	}

	// We need at least one parity shard to recover
	var parityShard []byte
	for i := c.dataShards; i < len(shards); i++ {
		if shards[i] != nil {
			parityShard = shards[i]
			break
		}
	}
	if parityShard == nil {
		return nil, fmt.Errorf("cannot recover: all parity shards are missing")
	}

	// Check if we have all other data shards
	for i := 0; i < c.dataShards; i++ {
		if i != missingIdx && shards[i] == nil {
			return nil, fmt.Errorf("cannot recover: multiple data shards missing (index %d and %d)", missingIdx, i)
		}
	}

	// Reconstruct by XORing all other data shards and the parity shard
	recovered := make([]byte, len(parityShard))
	copy(recovered, parityShard)

	for i := 0; i < c.dataShards; i++ {
		if i != missingIdx {
			for idx := range shards[i] {
				recovered[idx] ^= shards[i][idx]
			}
		}
	}

	return recovered, nil
}
