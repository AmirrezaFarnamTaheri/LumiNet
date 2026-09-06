package security

import (
	"sync"
)

type EndpointProfile struct {
	ProfileID       string
	ServerHost      string
	ServerPort      uint16
	Username        string
	EncryptedSecret []byte
	CreatedAtSec    uint64
	ExpiresAtSec    uint64
}

type EndpointCredentialVault struct {
	mu        sync.RWMutex
	profiles  map[string]EndpointProfile
	masterKey [32]byte
}

func NewEndpointCredentialVault(masterKey [32]byte) *EndpointCredentialVault {
	return &EndpointCredentialVault{
		profiles:  make(map[string]EndpointProfile),
		masterKey: masterKey,
	}
}

func (v *EndpointCredentialVault) StoreProfile(profileID, host string, port uint16, user string, rawSecret []byte, nowSec, ttlSec uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()

	enc := make([]byte, len(rawSecret))
	copy(enc, rawSecret)
	for i := range enc {
		enc[i] ^= v.masterKey[i%32]
	}

	v.profiles[profileID] = EndpointProfile{
		ProfileID:       profileID,
		ServerHost:      host,
		ServerPort:      port,
		Username:        user,
		EncryptedSecret: enc,
		CreatedAtSec:    nowSec,
		ExpiresAtSec:    nowSec + ttlSec,
	}
}

func (v *EndpointCredentialVault) RetrieveSecret(profileID string, nowSec uint64) ([]byte, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	p, ok := v.profiles[profileID]
	if !ok || nowSec > p.ExpiresAtSec {
		return nil, false
	}

	dec := make([]byte, len(p.EncryptedSecret))
	copy(dec, p.EncryptedSecret)
	for i := range dec {
		dec[i] ^= v.masterKey[i%32]
	}

	return dec, true
}

func (v *EndpointCredentialVault) IsProfileValid(profileID string, nowSec uint64) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	p, ok := v.profiles[profileID]
	if !ok {
		return false
	}
	return nowSec <= p.ExpiresAtSec
}

func (v *EndpointCredentialVault) PurgeExpired(nowSec uint64) int {
	v.mu.Lock()
	defer v.mu.Unlock()

	before := len(v.profiles)
	for id, p := range v.profiles {
		if nowSec > p.ExpiresAtSec {
			delete(v.profiles, id)
		}
	}
	return before - len(v.profiles)
}
