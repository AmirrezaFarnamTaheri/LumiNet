package safety

import (
	"sync"
)

type PeerAclEvaluator struct {
	mu           sync.RWMutex
	defaultAllow bool
	explicitAcl  map[string]map[string]bool
}

func NewPeerAclEvaluator(defaultAllow bool) *PeerAclEvaluator {
	return &PeerAclEvaluator{
		defaultAllow: defaultAllow,
		explicitAcl:  make(map[string]map[string]bool),
	}
}

func (e *PeerAclEvaluator) SetRule(sourcePeer, targetPeer string, allowed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.explicitAcl[sourcePeer]; !exists {
		e.explicitAcl[sourcePeer] = make(map[string]bool)
	}
	e.explicitAcl[sourcePeer][targetPeer] = allowed
}

func (e *PeerAclEvaluator) IsAllowed(sourcePeer, targetPeer string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if row, exists := e.explicitAcl[sourcePeer]; exists {
		if allowed, found := row[targetPeer]; found {
			return allowed
		}
	}
	return e.defaultAllow
}

func (e *PeerAclEvaluator) ClearRules() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.explicitAcl = make(map[string]map[string]bool)
}
