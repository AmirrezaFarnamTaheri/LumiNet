//go:build !windows

package cmd

import "syscall"

func prepareWatchdogSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
