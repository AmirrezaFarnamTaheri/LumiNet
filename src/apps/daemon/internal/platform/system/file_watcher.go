package system

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const defaultConfigWatcherDebounce = 250 * time.Millisecond

type pendingCallback struct {
	generation uint64
	timer      *time.Timer
}

// ConfigWatcher monitors exact configuration file paths while subscribing to
// their parent directories. Watching the directory instead of the file keeps
// the watch alive when an editor or LumiNet itself publishes a new file with
// the common temp-file + atomic-rename pattern.
type ConfigWatcher struct {
	watcher     *fsnotify.Watcher
	watchPaths  map[string]struct{}
	callback    func(string)
	waitTimeout time.Duration
	timerMap    map[string]pendingCallback
	errors      chan error
	mu          sync.Mutex
	closed      bool
}

// NewConfigWatcher initializes a debounced watcher for exact file paths.
// Paths are canonicalized to absolute cleaned names, duplicate parent
// directories are subscribed only once, and the caller's slice is never kept.
func NewConfigWatcher(paths []string, callback func(string), timeout time.Duration) (*ConfigWatcher, error) {
	if callback == nil {
		return nil, fmt.Errorf("config_watcher: callback is required")
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("config_watcher: at least one path is required")
	}
	if timeout <= 0 {
		timeout = defaultConfigWatcherDebounce
	}

	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &ConfigWatcher{
		watcher:     fsWatcher,
		watchPaths:  make(map[string]struct{}, len(paths)),
		callback:    callback,
		waitTimeout: timeout,
		timerMap:    make(map[string]pendingCallback),
		errors:      make(chan error, 8),
	}

	watchDirs := make(map[string]struct{})
	for _, path := range paths {
		if path == "" {
			_ = fsWatcher.Close()
			return nil, fmt.Errorf("config_watcher: empty path")
		}
		abs, err := filepath.Abs(filepath.Clean(path))
		if err != nil {
			_ = fsWatcher.Close()
			return nil, fmt.Errorf("config_watcher: canonicalize %q: %w", path, err)
		}
		w.watchPaths[abs] = struct{}{}
		watchDirs[filepath.Dir(abs)] = struct{}{}
	}

	for dir := range watchDirs {
		if err := w.watcher.Add(dir); err != nil {
			_ = fsWatcher.Close()
			return nil, fmt.Errorf("config_watcher: watch parent %q: %w", dir, err)
		}
	}

	go w.loop()
	return w, nil
}

// Errors reports asynchronous backend errors without terminating the watcher.
// Delivery is best-effort and bounded; callers that do not consume it cannot
// deadlock filesystem event processing.
func (w *ConfigWatcher) Errors() <-chan error { return w.errors }

func (w *ConfigWatcher) loop() {
	defer close(w.errors)
	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			path, err := filepath.Abs(filepath.Clean(event.Name))
			if err != nil {
				w.reportError(fmt.Errorf("config_watcher: canonicalize event path: %w", err))
				continue
			}
			if _, watched := w.watchPaths[path]; !watched {
				continue
			}
			// Write covers in-place saves; Create/Rename covers atomic publish;
			// Remove is material too because deletion changes configuration state.
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
				w.schedule(path)
			}
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			if err != nil {
				w.reportError(err)
			}
		}
	}
}

func (w *ConfigWatcher) reportError(err error) {
	select {
	case w.errors <- err:
	default:
	}
}

func (w *ConfigWatcher) schedule(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}

	pending := w.timerMap[path]
	gen := pending.generation + 1
	if pending.timer != nil {
		pending.timer.Stop()
	}

	w.timerMap[path] = pendingCallback{
		generation: gen,
		timer:      time.AfterFunc(w.waitTimeout, func() { w.fire(path, gen) }),
	}
}

func (w *ConfigWatcher) fire(path string, gen uint64) {
	w.mu.Lock()
	pending, exists := w.timerMap[path]
	if !exists || pending.generation != gen || w.closed {
		w.mu.Unlock()
		return
	}
	delete(w.timerMap, path)
	w.mu.Unlock()

	w.callback(path)
}

// Close terminates fsnotify and stops pending reloads.
func (w *ConfigWatcher) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	for _, pending := range w.timerMap {
		if pending.timer != nil {
			pending.timer.Stop()
		}
	}
	w.timerMap = make(map[string]pendingCallback)
	w.mu.Unlock()
	return w.watcher.Close()
}
