//go:build windows

package bridge

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	PAGE_READWRITE = 0x04
	FILE_MAP_WRITE = 0x02
)

//go:nocheckptr
func mapMemory(size int) ([]byte, error) {
	// Allocate shared memory via file mapping
	// syscall.InvalidHandle maps memory from system paging file (anonymous map)
	handle, err := syscall.CreateFileMapping(
		syscall.InvalidHandle,
		nil,
		PAGE_READWRITE,
		0,
		uint32(size),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateFileMapping failed: %w", err)
	}
	defer syscall.CloseHandle(handle)

	addr, err := syscall.MapViewOfFile(
		handle,
		FILE_MAP_WRITE,
		0,
		0,
		uintptr(size),
	)
	if err != nil {
		return nil, fmt.Errorf("MapViewOfFile failed: %w", err)
	}

	ptr := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	return unsafe.Slice((*byte)(ptr), size), nil
}

func unmapMemory(data []byte) error {
	addr := unsafe.SliceData(data)
	return syscall.UnmapViewOfFile(uintptr(unsafe.Pointer(addr)))
}
