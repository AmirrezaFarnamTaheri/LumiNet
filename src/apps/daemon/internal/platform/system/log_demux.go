//
// LogDemux fans a single log stream out to multiple named sinks (files,
// ring buffers, WebSocket clients) with per-sink filtering and rotation.

package system

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// LogSink is an output destination for demultiplexed log lines.
type LogSink interface {
	// Write receives a log line. Called from a goroutine; must be thread-safe.
	Write(line string) error
	// Close flushes and releases the sink.
	Close() error
}

// FilteredSink wraps a LogSink and forwards only lines containing a keyword.
type FilteredSink struct {
	inner   LogSink
	keyword string
}

func (f *FilteredSink) Write(line string) error {
	if f.keyword == "" || strings.Contains(line, f.keyword) {
		return f.inner.Write(line)
	}
	return nil
}
func (f *FilteredSink) Close() error { return f.inner.Close() }

// FileSink writes log lines to a file, creating it if necessary.
type FileSink struct {
	mu   sync.Mutex
	file *os.File
	path string
}

func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("log_demux: open file sink %s: %w", path, err)
	}
	return &FileSink{file: f, path: path}, nil
}

func (s *FileSink) Write(line string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := fmt.Fprintf(s.file, "%s %s\n", time.Now().Format(time.RFC3339), line)
	return err
}

func (s *FileSink) Close() error { return s.file.Close() }

// RingBufferSink retains the last N log lines in memory for API serving.
type RingBufferSink struct {
	mu      sync.RWMutex
	buf     []string
	cap     int
	head    int
	written int
}

func NewRingBufferSink(cap int) *RingBufferSink {
	return &RingBufferSink{buf: make([]string, cap), cap: cap}
}

func (r *RingBufferSink) Write(line string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.head%r.cap] = line
	r.head++
	r.written++
	return nil
}

// Snapshot returns recent log lines in order from oldest to newest.
func (r *RingBufferSink) Snapshot() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.written <= r.cap {
		result := make([]string, r.head)
		copy(result, r.buf[:r.head])
		return result
	}
	result := make([]string, r.cap)
	start := r.head % r.cap
	copy(result, r.buf[start:])
	copy(result[r.cap-start:], r.buf[:start])
	return result
}

func (r *RingBufferSink) Close() error { return nil }

// LogDemux reads from a source reader and fans out to registered sinks.
type LogDemux struct {
	mu    sync.RWMutex
	sinks map[string]LogSink
	done  chan struct{}
	wg    sync.WaitGroup
}

func NewLogDemux() *LogDemux {
	return &LogDemux{
		sinks: make(map[string]LogSink),
		done:  make(chan struct{}),
	}
}

// AddSink registers a named sink. Replaces any existing sink with the same name.
func (d *LogDemux) AddSink(name string, sink LogSink) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if old, ok := d.sinks[name]; ok {
		old.Close()
	}
	d.sinks[name] = sink
}

// AddFilteredSink registers a sink that only receives lines matching keyword.
func (d *LogDemux) AddFilteredSink(name, keyword string, sink LogSink) {
	d.AddSink(name, &FilteredSink{inner: sink, keyword: keyword})
}

// RemoveSink unregisters and closes a named sink.
func (d *LogDemux) RemoveSink(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s, ok := d.sinks[name]; ok {
		s.Close()
		delete(d.sinks, name)
	}
}

// Start begins reading from r and dispatching lines to all sinks.
// Blocks until r returns EOF or Close is called.
func (d *LogDemux) Start(r io.Reader) {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			select {
			case <-d.done:
				return
			default:
			}
			line := scanner.Text()
			d.mu.RLock()
			for _, sink := range d.sinks {
				_ = sink.Write(line)
			}
			d.mu.RUnlock()
		}
	}()
}

// Close stops the demux and closes all sinks.
func (d *LogDemux) Close() {
	close(d.done)
	d.wg.Wait()
	d.mu.Lock()
	defer d.mu.Unlock()
	for name, sink := range d.sinks {
		sink.Close()
		delete(d.sinks, name)
	}
}
