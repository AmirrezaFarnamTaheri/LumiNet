package proxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/config"
	"github.com/maybeknott/luminet/internal/platform/system"
)

// ConfigWatcher is the runtime-facing adapter for the canonical filesystem
// ConfigWatcher. It intentionally does not own reconciliation: it reloads the
// durable config authority and then notifies registered consumers, which must
// decide how to reconcile their own runtime state.
type ConfigWatcher struct {
	manager    *config.Manager
	configPath string
	debounce   time.Duration

	mu           sync.Mutex
	callbacks    []func(*config.Config)
	watcher      *system.ConfigWatcher
	running      bool
	lastRevision uint64
}

// NewConfigWatcher creates a watcher adapter. Atomic file replacement is
// handled by platform/system.ConfigWatcher by watching the parent directory.
func NewConfigWatcher(manager *config.Manager, configPath string, debounce time.Duration) *ConfigWatcher {
	if debounce <= 0 {
		debounce = 250 * time.Millisecond
	}
	return &ConfigWatcher{manager: manager, configPath: configPath, debounce: debounce}
}

// OnChange registers a runtime reconciliation callback. Nil callbacks are
// ignored so one bad registration cannot panic the watcher goroutine.
func (w *ConfigWatcher) OnChange(callback func(*config.Config)) {
	if callback == nil {
		return
	}
	w.mu.Lock()
	w.callbacks = append(w.callbacks, callback)
	w.mu.Unlock()
}

// Start begins exact-path filesystem observation. Setup failures are returned
// synchronously instead of silently degrading to a polling/no-op state.
func (w *ConfigWatcher) Start(ctx context.Context) error {
	if w == nil || w.manager == nil {
		return fmt.Errorf("config_watcher: manager is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	watcher, err := system.NewConfigWatcher([]string{w.configPath}, w.reload, w.debounce)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	w.watcher = watcher
	w.running = true
	w.lastRevision = w.manager.Revision()
	w.mu.Unlock()

	go func() {
		for {
			select {
			case <-ctx.Done():
				_ = w.Stop()
				return
			case _, ok := <-watcher.Errors():
				if !ok {
					return
				}
				// Backend errors are bounded diagnostic signals. Keep consuming
				// them so event delivery can continue without a hidden deadlock.
			}
		}
	}()
	return nil
}

func (w *ConfigWatcher) reload(string) {
	cfg, err := w.manager.Load()
	if err != nil {
		return
	}
	w.mu.Lock()
	if cfg.ConfigRevision == w.lastRevision {
		w.mu.Unlock()
		return
	}
	w.lastRevision = cfg.ConfigRevision
	callbacks := append([]func(*config.Config){}, w.callbacks...)
	w.mu.Unlock()
	for _, cb := range callbacks {
		cb(cfg)
	}
}

// Stop terminates the canonical watcher and is idempotent.
func (w *ConfigWatcher) Stop() error {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return nil
	}
	watcher := w.watcher
	w.watcher = nil
	w.running = false
	w.mu.Unlock()
	if watcher != nil {
		return watcher.Close()
	}
	return nil
}
