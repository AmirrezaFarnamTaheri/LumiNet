//go:build !linux && !windows

package tarpit

func configureSocket(fd uintptr) {}
