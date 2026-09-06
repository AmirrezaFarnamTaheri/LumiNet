package jobs

import (
	"sync"
	"time"
)

// BatchedRecords is one flush of the log batcher: whatever accumulated before
// the size or time trigger fired first.
type BatchedRecords[T any] struct {
	Records []T
	// Trigger reports what ended the batch: "size", "time", or "close".
	Trigger string
}

// LogBatcherOptions configures a LogBatcher.
type LogBatcherOptions[T any] struct {
	// MaxRecords ends a batch as soon as this many records accumulate.
	MaxRecords int
	// MaxInterval ends a batch after this long even if it is not full.
	MaxInterval time.Duration
	// Out receives every completed batch. Must not be nil; FlushOnClose
	// semantics depend on the consumer draining it.
	Out chan<- BatchedRecords[T]
}

// LogBatcher accumulates records and emits them in batches bounded by count
// (MaxRecords) or time (MaxInterval), whichever fires first: an overflow-safe producer feeds a single-threaded
// processor so downstream consumers never see concurrent sends.
//
// Zero-value MaxRecords/MaxInterval fall back to 64 records / 5 seconds.
type LogBatcher[T any] struct {
	opts     LogBatcherOptions[T]
	mu       sync.Mutex
	buffer   []T
	timer    *time.Timer
	closed   bool
	flushing bool
	wg       sync.WaitGroup
}

// NewLogBatcher starts batching; call Close to flush and stop the timer.
func NewLogBatcher[T any](opts LogBatcherOptions[T]) *LogBatcher[T] {
	if opts.MaxRecords <= 0 {
		opts.MaxRecords = 64
	}
	if opts.MaxInterval <= 0 {
		opts.MaxInterval = 5 * time.Second
	}
	b := &LogBatcher[T]{opts: opts}
	b.timer = time.AfterFunc(opts.MaxInterval, b.onTimer)
	return b
}

// Add enqueues one record, flushing early when the size trigger fires.
func (b *LogBatcher[T]) Add(record T) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.buffer = append(b.buffer, record)
	if len(b.buffer) >= b.opts.MaxRecords && !b.flushing {
		b.flushLocked("size")
	}
	b.mu.Unlock()
}

func (b *LogBatcher[T]) onTimer() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || len(b.buffer) == 0 {
		// Rearm while open so idle producers still get periodic no-op ticks;
		// empty batches are suppressed.
		if !b.closed {
			b.timer.Reset(b.opts.MaxInterval)
		}
		return
	}
	b.flushLocked("time")
}

func (b *LogBatcher[T]) flushLocked(trigger string) {
	if len(b.buffer) == 0 {
		return
	}
	batch := b.buffer
	b.buffer = nil
	if b.opts.Out == nil {
		return
	}
	// Emit outside the lock is impossible with an unbuffered consumer channel;
	// deliver under the lock but guard reentrancy via flushing flag.
	b.flushing = true
	defer func() { b.flushing = false }()
	select {
	case b.opts.Out <- BatchedRecords[T]{Records: batch, Trigger: trigger}:
	default:
		// Consumer is not keeping up: coalesce into the next batch rather than
		// blocking the producer path.
		b.buffer = append(batch, b.buffer...)
	}
	if trigger == "time" && !b.closed {
		b.timer.Reset(b.opts.MaxInterval)
	}
}

// Flush synchronously emits whatever is buffered.
func (b *LogBatcher[T]) Flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flushLocked("close")
}

// Close stops the timer and flushes remaining records. Further Adds are ignored.
func (b *LogBatcher[T]) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	b.timer.Stop()
	b.flushLocked("close")
	b.mu.Unlock()
}
