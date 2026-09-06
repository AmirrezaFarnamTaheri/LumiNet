package proxy

import (
	"sync"
	"sync/atomic"
)

type MultiPathBalancer struct {
	paths []string
	idx   uint64
	mu    sync.RWMutex
}

func NewMultiPathBalancer(paths []string) *MultiPathBalancer {
	return &MultiPathBalancer{paths: paths}
}

func (b *MultiPathBalancer) SelectNextPath() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.paths) == 0 {
		return ""
	}
	n := atomic.AddUint64(&b.idx, 1)
	return b.paths[n%uint64(len(b.paths))]
}
