package proxy

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPool_SubmitAndShutdown(t *testing.T) {
	pool := NewWorkerPool(4)
	var count int64

	for i := 0; i < 100; i++ {
		pool.Submit(func() {
			atomic.AddInt64(&count, 1)
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pool.Shutdown(ctx)

	if atomic.LoadInt64(&count) != 100 {
		t.Errorf("expected 100 jobs executed, got %d", atomic.LoadInt64(&count))
	}
}
