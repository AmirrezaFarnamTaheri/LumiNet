//go:build !windows && !linux

package proxy

func getSystemTotalMemory() uint64 {
	return 0
}
