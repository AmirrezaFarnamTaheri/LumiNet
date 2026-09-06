package relay

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

// RelayHeader contains routing metadata for onion relay hops.
type RelayHeader struct {
	SessionID [16]byte
	NextHop   string
	TTL       uint8
}

// RelayChain encapsulates N-layer ChaCha20-Poly1305 onion encryption.
type RelayChain struct {
	HopKeys [][32]byte
}

// NewRelayChain creates a multi-hop onion relay chain with hopKeys.
func NewRelayChain(hopKeys [][32]byte) (*RelayChain, error) {
	if len(hopKeys) == 0 {
		return nil, errors.New("at least one hop key is required")
	}
	return &RelayChain{HopKeys: hopKeys}, nil
}

// Encrypt payload in N layers of ChaCha20-Poly1305 (innermost to outermost).
func (rc *RelayChain) Encrypt(payload []byte) ([]byte, error) {
	current := payload
	for i := len(rc.HopKeys) - 1; i >= 0; i-- {
		aead, err := chacha20poly1305.NewX(rc.HopKeys[i][:])
		if err != nil {
			return nil, err
		}

		nonce := make([]byte, aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}

		sealed := aead.Seal(nil, nonce, current, nil)
		current = append(nonce, sealed...)
	}
	return current, nil
}

// DecryptLayer peels one layer of encryption using hopKey.
func DecryptLayer(hopKey [32]byte, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(hopKey[:])
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("data too short for XChaCha20-Poly1305 nonce")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	return aead.Open(nil, nonce, ciphertext, nil)
}
