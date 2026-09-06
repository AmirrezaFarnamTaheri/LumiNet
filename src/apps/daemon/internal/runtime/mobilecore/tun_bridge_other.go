//go:build !unix && !android

package mobilecore

func dupFdPlatform(fd int) (int, error) {
	// Fallback on Windows/non-Unix development targets: preserve valid fd
	return fd, nil
}
