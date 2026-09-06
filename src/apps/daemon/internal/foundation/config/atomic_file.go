package config

import (
	"fmt"
	"os"
)

// writeAtomicPrivateFile persists sensitive configuration through a private
// temporary file, flushes its bytes before publication, and removes the
// temporary file on every failed path.
func writeAtomicPrivateFile(path string, data []byte) (err error) {
	tmpPath := path + ".tmp"
	file, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = file.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write temporary config: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary config: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("publish config: %w", err)
	}
	published = true
	return nil
}
