//go:build !linux

package securefs

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

func initSecureFS() error {
	if secureDir != "" {
		return nil
	}
	dir, err := os.MkdirTemp("", "luminet-secure-*")
	if err != nil {
		return err
	}
	secureDir = dir
	return nil
}

func writeFile(filename string, data []byte, perm os.FileMode) (string, error) {
	if secureDir == "" {
		return "", fmt.Errorf("secure filesystem not initialized")
	}
	filePath := filepath.Join(secureDir, filename)
	err := os.WriteFile(filePath, data, perm)
	if err != nil {
		return "", err
	}
	return filePath, nil
}

func readFile(filename string) ([]byte, error) {
	if secureDir == "" {
		return nil, fmt.Errorf("secure filesystem not initialized")
	}
	filePath := filepath.Join(secureDir, filename)
	return os.ReadFile(filePath)
}

func shredFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	size := info.Size()
	if size == 0 {
		return os.Remove(path)
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	// Pass 1: overwrite with random bytes
	randomBytes := make([]byte, 4096)
	var written int64
	for written < size {
		toWrite := size - written
		if toWrite > int64(len(randomBytes)) {
			toWrite = int64(len(randomBytes))
		}
		if _, err := rand.Read(randomBytes[:toWrite]); err != nil {
			return err
		}
		n, err := f.Write(randomBytes[:toWrite])
		if err != nil {
			return err
		}
		written += int64(n)
	}
	if err := f.Sync(); err != nil {
		return err
	}

	// Seek back to start
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}

	// Pass 2: overwrite with zeroes
	zeroes := make([]byte, 4096)
	written = 0
	for written < size {
		toWrite := size - written
		if toWrite > int64(len(zeroes)) {
			toWrite = int64(len(zeroes))
		}
		n, err := f.Write(zeroes[:toWrite])
		if err != nil {
			return err
		}
		written += int64(n)
	}
	if err := f.Sync(); err != nil {
		return err
	}

	f.Close()
	return os.Remove(path)
}

func cleanupSecureFS() {
	if secureDir == "" {
		return
	}
	files, err := os.ReadDir(secureDir)
	if err == nil {
		for _, file := range files {
			if !file.IsDir() {
				_ = shredFile(filepath.Join(secureDir, file.Name()))
			}
		}
	}
	_ = os.RemoveAll(secureDir)
	secureDir = ""
}
