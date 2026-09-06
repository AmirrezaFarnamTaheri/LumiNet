//go:build unix || android

package mobilecore

import "syscall"

func dupFdPlatform(fd int) (int, error) {
	newFd, err := syscall.Dup(fd)
	if err != nil {
		return -1, err
	}
	return newFd, nil
}
