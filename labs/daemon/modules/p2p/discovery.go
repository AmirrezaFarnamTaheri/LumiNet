// Package p2p provides peer-to-peer mesh networking capabilities.
package p2p

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"sync"
)

// NodeID is a 256-bit identifier derived from SHA-256 of Ed25519 public key.
type NodeID [32]byte

// PeerInfo holds connection parameters for a mesh peer.
type PeerInfo struct {
	ID      NodeID
	Address string
	PubKey  ed25519.PublicKey
}

// KBucket represents a Kademlia routing table bucket (Capacity k=20).
type KBucket struct {
	mu    sync.RWMutex
	peers []PeerInfo
}

// RoutingTable manages 256 Kademlia buckets for peer discovery.
type RoutingTable struct {
	Self    NodeID
	Buckets [256]*KBucket
}

// NewRoutingTable creates and initializes a RoutingTable for selfID.
func NewRoutingTable(pubKey ed25519.PublicKey) *RoutingTable {
	hash := sha256.Sum256(pubKey)
	rt := &RoutingTable{Self: hash}
	for i := 0; i < 256; i++ {
		rt.Buckets[i] = &KBucket{peers: make([]PeerInfo, 0, 20)}
	}
	return rt
}

// Distance calculates XOR metric distance between two NodeIDs.
func Distance(a, b NodeID) *big.Int {
	var c [32]byte
	for i := 0; i < 32; i++ {
		c[i] = a[i] ^ b[i]
	}
	return new(big.Int).SetBytes(c[:])
}

// Insert adds a peer into the appropriate bucket based on XOR distance metric.
func (rt *RoutingTable) Insert(peer PeerInfo) bool {
	dist := Distance(rt.Self, peer.ID)
	bucketIdx := 255 - dist.BitLen()
	if bucketIdx < 0 {
		bucketIdx = 0
	}
	if bucketIdx >= 256 {
		bucketIdx = 255
	}

	b := rt.Buckets[bucketIdx]
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, existing := range b.peers {
		if existing.ID == peer.ID {
			b.peers[i] = peer // Update existing entry
			return true
		}
	}

	if len(b.peers) < 20 {
		b.peers = append(b.peers, peer)
		return true
	}
	return false // Bucket full
}

// FindClosest returns up to count nearest peers to target NodeID.
func (rt *RoutingTable) FindClosest(target NodeID, count int) []PeerInfo {
	var result []PeerInfo
	for i := 0; i < 256 && len(result) < count; i++ {
		b := rt.Buckets[i]
		b.mu.RLock()
		for _, p := range b.peers {
			result = append(result, p)
			if len(result) >= count {
				b.mu.RUnlock()
				return result
			}
		}
		b.mu.RUnlock()
	}
	return result
}

// GenerateNodeID generates a fresh Ed25519 public key and corresponding NodeID.
func GenerateNodeID() (ed25519.PublicKey, ed25519.PrivateKey, NodeID, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, NodeID{}, err
	}
	id := sha256.Sum256(pub)
	return pub, priv, id, nil
}
