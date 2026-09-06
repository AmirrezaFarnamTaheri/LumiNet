package proxy

import (
	"context"
	"runtime"
	"sync"
)

// WorkerPool manages a fixed-size pool of worker goroutines for background proxy tasks.
type WorkerPool struct {
	work chan func()
	wg   sync.WaitGroup
	once sync.Once
}

// NewWorkerPool creates a new WorkerPool with specified size (defaults to GOMAXPROCS * 4).
func NewWorkerPool(size int) *WorkerPool {
	if size <= 0 {
		size = runtime.GOMAXPROCS(0) * 4
	}
	p := &WorkerPool{
		work: make(chan func(), 1024),
	}
	for i := 0; i < size; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for fn := range p.work {
				fn()
			}
		}()
	}
	return p
}

// Submit enqueues a job into the worker pool.
func (p *WorkerPool) Submit(fn func()) bool {
	select {
	case p.work <- fn:
		return true
	default:
		// Queue full: fallback to executing inline or dropping
		go fn()
		return false
	}
}

// Shutdown gracefully stops the worker pool after completing pending tasks.
func (p *WorkerPool) Shutdown(ctx context.Context) {
	p.once.Do(func() {
		close(p.work)
	})

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}
