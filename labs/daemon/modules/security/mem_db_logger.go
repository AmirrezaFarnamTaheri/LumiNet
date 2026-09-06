// Package security handles intrusion detection and firewall hooks.
package security

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const memSegSize = 64 * 1024

// LogEntry is a structured in-memory log record.
type LogEntry struct {
	Timestamp time.Time      `json:"ts"`
	Level     string         `json:"level"`
	Message   string         `json:"msg"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// MemDBLogger is a page-aligned ring log with AOF replay.
type MemDBLogger struct {
	mu      sync.RWMutex
	segs    [][]byte
	entries []LogEntry
	maxSegs int
	written uint64
}

func NewMemDBLogger(maxSegments int) *MemDBLogger {
	if maxSegments <= 0 {
		maxSegments = 16
	}
	return &MemDBLogger{maxSegs: maxSegments}
}

// Log appends a structured entry to the ring.
func (m *MemDBLogger) Log(level, message string, fields map[string]any) error {
	entry := LogEntry{Timestamp: time.Now().UTC(), Level: level, Message: message, Fields: fields}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("MemDBLogger.Log: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.segs) == 0 || len(m.segs[len(m.segs)-1])+len(data)+1 > memSegSize {
		if len(m.segs) >= m.maxSegs {
			m.segs = m.segs[1:]
		}
		m.segs = append(m.segs, make([]byte, 0, memSegSize))
	}
	seg := &m.segs[len(m.segs)-1]
	*seg = append(*seg, data...)
	*seg = append(*seg, '\n')
	m.written += uint64(len(data) + 1)
	m.entries = append(m.entries, entry)
	return nil
}

// Replay returns all entries in chronological order.
func (m *MemDBLogger) Replay() []LogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]LogEntry, len(m.entries))
	copy(out, m.entries)
	return out
}

// BytesWritten returns total bytes written.
func (m *MemDBLogger) BytesWritten() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.written
}