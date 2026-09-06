package proxy

import (
	"crypto/ed25519"
	"errors"
	"sync"
)

type HypercoreFeed struct {
	mu        sync.RWMutex
	publicKey ed25519.PublicKey
	blocks    [][]byte
}

func NewHypercoreFeed(pubKey ed25519.PublicKey) *HypercoreFeed {
	return &HypercoreFeed{
		publicKey: pubKey,
		blocks:    make([][]byte, 0),
	}
}

func (h *HypercoreFeed) Append(block []byte, signature []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Verify cryptographic signature of the block if public key is available
	if h.publicKey != nil && len(signature) > 0 {
		if !ed25519.Verify(h.publicKey, block, signature) {
			return errors.New("invalid cryptographic signature for append-only log block")
		}
	}

	h.blocks = append(h.blocks, block)
	return nil
}

func (h *HypercoreFeed) Length() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.blocks)
}

func (h *HypercoreFeed) GetBlock(index int) ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if index < 0 || index >= len(h.blocks) {
		return nil, errors.New("index out of bounds")
	}
	return h.blocks[index], nil
}
