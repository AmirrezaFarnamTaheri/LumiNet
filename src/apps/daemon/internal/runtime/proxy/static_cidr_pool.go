package proxy

import (
	"errors"
	"net"
	"sync"
)

type StaticClientRecord struct {
	ClientID   string `json:"client_id"`
	AllocatedIP net.IP `json:"allocated_ip"`
	PublicKey  string `json:"public_key"`
	IsRevoked  bool   `json:"is_revoked"`
}

type StaticCidrPool struct {
	mu          sync.Mutex
	basePrefix  [3]byte
	nextHost    byte
	allocated   map[string]*StaticClientRecord
	revokedKeys map[string]bool
}

func NewStaticCidrPool(prefix [3]byte) *StaticCidrPool {
	return &StaticCidrPool{
		basePrefix:  prefix,
		nextHost:    2,
		allocated:   make(map[string]*StaticClientRecord),
		revokedKeys: make(map[string]bool),
	}
}

func (p *StaticCidrPool) AllocateClient(clientID, publicKey string) (*StaticClientRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.nextHost >= 254 {
		return nil, errors.New("cidr pool exhausted")
	}

	ip := net.IPv4(p.basePrefix[0], p.basePrefix[1], p.basePrefix[2], p.nextHost)
	p.nextHost++

	rec := &StaticClientRecord{
		ClientID:    clientID,
		AllocatedIP: ip,
		PublicKey:   publicKey,
		IsRevoked:   false,
	}
	p.allocated[ip.String()] = rec
	return rec, nil
}

func (p *StaticCidrPool) RevokeClient(ip net.IP) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if rec, exists := p.allocated[ip.String()]; exists {
		rec.IsRevoked = true
		p.revokedKeys[rec.PublicKey] = true
		return true
	}
	return false
}

func (p *StaticCidrPool) IsKeyRevoked(pubKey string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revokedKeys[pubKey]
}
