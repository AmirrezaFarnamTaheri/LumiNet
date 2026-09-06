package proxy

import "sync"

type FallbackDNSPool struct {
	mu        sync.RWMutex
	resolvers []string
}

func NewFallbackDNSPool() *FallbackDNSPool {
	return &FallbackDNSPool{
		resolvers: []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"},
	}
}

func (p *FallbackDNSPool) GetResolvers() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.resolvers
}
