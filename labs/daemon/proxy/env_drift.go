package proxy

// Ported from: env-drift-detector-main
// Target: server/internal/proxy/env_drift.go

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
	"sync"
)

// EnvDrift tracks configuration drift between deployed environments.
type EnvDrift struct {
	baseline map[string]string
	mu       sync.RWMutex
}

// NewEnvDrift creates an environment drift detector.
func NewEnvDrift() *EnvDrift {
	return &EnvDrift{baseline: make(map[string]string)}
}

// CaptureBaseline records current env file hashes.
func (e *EnvDrift) CaptureBaseline(files []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, f := range files {
		h, err := e.fileHash(f)
		if err != nil {
			log.Printf("EnvDrift: baseline capture failed for %s: %v", f, err)
			continue
		}
		e.baseline[f] = h
	}
}

// Detect reports files that changed since baseline.
func (e *EnvDrift) Detect(files []string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var drifted []string
	for _, f := range files {
		h, err := e.fileHash(f)
		if err != nil {
			continue
		}
		if e.baseline[f] != h {
			drifted = append(drifted, f)
		}
	}
	return drifted
}

// DriftCount returns number of drifted files.
func (e *EnvDrift) DriftCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.baseline)
}

func (e *EnvDrift) fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Digest computes a combined baseline fingerprint.
func (e *EnvDrift) Digest() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var buf bytes.Buffer
	for k, v := range e.baseline {
		buf.WriteString(k)
		buf.WriteString("=")
		buf.WriteString(v)
		buf.WriteByte('\n')
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}
