// Ported from: libXray-main
// Target path: server/internal/xray/libxray_wrapper.go

package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// ErrNativeCoreUnavailable reports that this build has no embedded Xray runtime.
var ErrNativeCoreUnavailable = errors.New("xray: embedded native core is unavailable in this build")

// XrayWrapper offers simplified APIs to initialize and control the native Xray core.
type XrayWrapper struct {
	mu        sync.RWMutex
	isRunning bool
}

// NewXrayWrapper creates a wrapper instance.
func NewXrayWrapper() *XrayWrapper {
	return &XrayWrapper{}
}

// RunXray starts the Xray core using a JSON configuration string.
func (w *XrayWrapper) RunXray(configJSON string) error {
	if _, err := TestConfig(configJSON); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.isRunning {
		return errors.New("libxray: xray is already running")
	}
	return ErrNativeCoreUnavailable
}

// StopXray terminates the running Xray core instance.
func (w *XrayWrapper) StopXray() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.isRunning {
		return nil
	}
	w.isRunning = false
	return nil
}

// IsRunning reports whether a real native Xray session is active.
func (w *XrayWrapper) IsRunning() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.isRunning
}

// QueryVersion returns the compiled Xray-core version string.
func QueryVersion() string {
	return "unavailable"
}

// TestConfig validates a JSON configuration structure.
func TestConfig(configJSON string) (bool, error) {
	if len(configJSON) == 0 {
		return false, fmt.Errorf("libxray: empty configuration")
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil || config == nil {
		return false, fmt.Errorf("libxray: invalid JSON configuration")
	}
	return true, nil
}
