// Package mobile — Android build tags: standard (non-root) build.
//
// Addresses P-02: Android Root/Standard Build Tags.
//
// This file is compiled only when:
//   GOOS=android AND the "android_root" build tag is NOT set.
//
// Standard builds use the Android VpnService API for routing, which
// requires no root privilege. Features that require root (WFP, raw sockets,
// kernel TUN) are excluded.

//go:build android && !android_root

package mobile

import "fmt"

// PlatformName identifies which Android variant is compiled.
const PlatformName = "android-standard"

// CanUseRawSockets reports whether the build has raw socket access.
// Standard builds never have raw socket access.
const CanUseRawSockets = false

// CanUseKernelTUN reports whether the build can open /dev/tun directly.
// Standard builds use the VpnService file descriptor instead.
const CanUseKernelTUN = false

// TUNProvider returns the tun.Device implementation appropriate for this
// build variant. Standard builds use the VpnService-provided file
// descriptor passed from the Java/Kotlin layer via SetTUNFd.
func TUNProvider() (string, error) {
	return "vpnservice-fd", nil
}

// RequiresRoot reports whether this build needs root.
func RequiresRoot() bool { return false }

// ValidatePrivileges checks whether necessary privileges are available
// for this build variant. Standard builds never need root.
func ValidatePrivileges() error {
	// VpnService is granted by the OS permission dialog — no root needed.
	return nil
}

// ProtectSocket is a no-op on standard Android builds: the VpnService
// protect() call must be made from the Java side via the bound service.
func ProtectSocket(fd int) error {
	return fmt.Errorf("ProtectSocket must be called from Java VpnService.protect() on standard Android builds (fd=%d)", fd)
}
