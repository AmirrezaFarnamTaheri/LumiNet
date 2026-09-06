package mobile

import (
	"os"
)

// CanFilter checks whether the process has read permissions for /proc/net/tcp
// and /proc/net/tcp6, which is required for Android UID lookup.
func CanFilter() bool {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return false
	}
	f.Close()

	f6, err := os.Open("/proc/net/tcp6")
	if err != nil {
		return false
	}
	f6.Close()

	return true
}
