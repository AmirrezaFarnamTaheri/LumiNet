//go:build windows

package crypto

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func withTPMRepositoryLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create TPM repository directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open TPM repository lock: %w", err)
	}
	defer file.Close()
	var overlapped windows.Overlapped
	handle := windows.Handle(file.Fd())
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		return fmt.Errorf("lock TPM repository: %w", err)
	}
	defer windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
	return fn()
}

func syncTPMDirectory(string) error {
	// Windows FlushFileBuffers on the renamed file is covered by syncing the
	// temporary file before MoveFileEx-backed os.Rename. Directory handles do
	// not support the same portable fsync contract.
	return nil
}
