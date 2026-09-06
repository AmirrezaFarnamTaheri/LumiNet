//go:build !windows

package system

import (
	"errors"
	"syscall"
)

func hostProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
