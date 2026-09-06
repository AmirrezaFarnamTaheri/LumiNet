// Package mobile — Android build tags: root build.
//
// Addresses P-02: Android Root/Standard Build Tags.
//
// This file is compiled only when:
//   GOOS=android AND the "android_root" build tag IS set.
//
// Root builds have access to raw sockets, kernel TUN (/dev/tun), and
// iptables for full transparent proxying without the VpnService API.
//
// Build command:
//
//	GOOS=android GOARCH=arm64 go build -tags android_root ./...

//go:build android && android_root

package mobile

import (
	"fmt"
	"os"
	"syscall"
)

// PlatformName identifies which Android variant is compiled.
const PlatformName = "android-root"

// CanUseRawSockets reports whether the build has raw socket access.
// Root builds always have raw socket access.
const CanUseRawSockets = true

// CanUseKernelTUN reports whether the build can open /dev/tun directly.
// Root builds open the kernel TUN device directly.
const CanUseKernelTUN = true

// TUNProvider returns the tun.Device implementation appropriate for this
// build variant. Root builds use the kernel TUN device.
func TUNProvider() (string, error) {
	if _, err := os.Stat("/dev/tun"); err != nil {
		return "", fmt.Errorf("android-root: /dev/tun not available: %w", err)
	}
	return "kernel-tun", nil
}

// RequiresRoot reports whether this build needs root.
func RequiresRoot() bool { return true }

// ValidatePrivileges checks whether root (UID 0) is available.
func ValidatePrivileges() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("android-root build requires root (uid=0), got uid=%d", os.Getuid())
	}
	return nil
}

// ProtectSocket bypasses the TUN for the given file descriptor using
// SO_MARK so that the socket's traffic is not re-intercepted.
// On root builds this is done in-process via a raw setsockopt.
func ProtectSocket(fd int) error {
	// MARK 1 is used by our iptables rules to exclude protected sockets.
	const PROTECTION_MARK = 1
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, PROTECTION_MARK)
}
