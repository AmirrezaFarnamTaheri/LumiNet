//go:build !windows

package bridge

import (
	"fmt"
	"syscall"
)

func mapMemory(size int) ([]byte, error) {
	data, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_ANONYMOUS)
	if err != nil {
		return nil, fmt.Errorf("mmap failed: %w", err)
	}
	return data, nil
}

func unmapMemory(data []byte) error {
	return syscall.Munmap(data)
}
