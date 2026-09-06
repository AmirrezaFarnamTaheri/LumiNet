//go:build linux

package proxy

import "syscall"

func setFileLimitPlatform() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		rLimit.Cur = 65536
		if rLimit.Max < 65536 {
			rLimit.Max = 65536
		}
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	}
}
