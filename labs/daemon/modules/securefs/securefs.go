package securefs

import (
	"os"
	"sync"
)

var (
	secureDir string
	mu        sync.RWMutex
)

// Init initializes the secure filesystem manager.
// On Linux, it mounts the virtual memory-only FUSE filesystem.
// On Windows/macOS/others, it sets up a securely shredded fallback temp directory.
func Init() error {
	mu.Lock()
	defer mu.Unlock()
	return initSecureFS()
}

// WriteFile writes a sensitive file (like config or keys) to the secure storage and returns its absolute path.
func WriteFile(filename string, data []byte, perm os.FileMode) (string, error) {
	mu.RLock()
	defer mu.RUnlock()
	return writeFile(filename, data, perm)
}

// ReadFile reads a sensitive file from the secure storage.
func ReadFile(filename string) ([]byte, error) {
	mu.RLock()
	defer mu.RUnlock()
	return readFile(filename)
}

// Cleanup unmounts the FUSE filesystem (on Linux) and deletes temporary fallback files securely.
func Cleanup() {
	mu.Lock()
	defer mu.Unlock()
	cleanupSecureFS()
}

// GetSecureDir returns the path to the secure folder.
func GetSecureDir() string {
	mu.Lock()
	defer mu.Unlock()
	return secureDir
}
