package transport

import (
	"bytes"
	"sync"
)

type ProbeAction string

const (
	ProbeActionAcceptStream  ProbeAction = "AcceptStream"
	ProbeActionDeflectToDecoy ProbeAction = "DeflectToDecoy"
	ProbeActionDropConnection ProbeAction = "DropConnection"
)

type CamouflageStreamMasquerader struct {
	mu           sync.RWMutex
	sharedSecret []byte
	validUserIDs [][16]byte
	decoyHost    string
}

func NewCamouflageStreamMasquerader(sharedSecret []byte, decoyHost string) *CamouflageStreamMasquerader {
	return &CamouflageStreamMasquerader{
		sharedSecret: append([]byte(nil), sharedSecret...),
		validUserIDs: make([][16]byte, 0),
		decoyHost:    decoyHost,
	}
}

func (m *CamouflageStreamMasquerader) RegisterUser(userID [16]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.validUserIDs = append(m.validUserIDs, userID)
}

func (m *CamouflageStreamMasquerader) GeneratePreamble(userID [16]byte) []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]byte, 32)
	salt := [16]byte{0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a}
	copy(out[0:16], salt[:])

	secLen := len(m.sharedSecret)
	if secLen == 0 {
		secLen = 1
	}

	for i := 0; i < 16; i++ {
		var secByte byte
		if len(m.sharedSecret) > 0 {
			secByte = m.sharedSecret[i%len(m.sharedSecret)]
		}
		mask := secByte ^ salt[i]
		out[16+i] = userID[i] ^ mask
	}
	return out
}

func (m *CamouflageStreamMasquerader) InspectInboundStream(preamble []byte) ProbeAction {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(preamble) < 32 {
		return ProbeActionDeflectToDecoy
	}

	salt := preamble[0:16]
	var uid [16]byte
	for i := 0; i < 16; i++ {
		var secByte byte
		if len(m.sharedSecret) > 0 {
			secByte = m.sharedSecret[i%len(m.sharedSecret)]
		}
		mask := secByte ^ salt[i]
		uid[i] = preamble[16+i] ^ mask
	}

	for _, valid := range m.validUserIDs {
		if bytes.Equal(valid[:], uid[:]) {
			return ProbeActionAcceptStream
		}
	}

	return ProbeActionDeflectToDecoy
}

func (m *CamouflageStreamMasquerader) DecoyHost() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.decoyHost
}
