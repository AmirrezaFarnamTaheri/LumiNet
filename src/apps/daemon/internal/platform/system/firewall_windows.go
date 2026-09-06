//go:build windows && cgo

package system

/*
#cgo LDFLAGS: -lfwpuclnt
#include "wfp_leak_prevention.h"
*/
import "C"

import (
	"context"
	"fmt"
	"net"
)

// DNSLeakProtectionSupported reports whether WFP DNS leak protection is compiled in.
func DNSLeakProtectionSupported() bool { return true }

// EnableDnsLeakProtection blocks outbound UDP DNS (port 53) on all physical network interfaces except the TUN interface using WFP.
func EnableDnsLeakProtection(ctx context.Context, tunDeviceName string) error {
	iface, err := net.InterfaceByName(tunDeviceName)
	if err != nil {
		return fmt.Errorf("failed to get interface by name %s: %w", tunDeviceName, err)
	}

	res := C.InitializeDnsLeakPreventer(C.UINT32(iface.Index))
	if res != 0 {
		return fmt.Errorf("WFP InitializeDnsLeakPreventer failed with code: 0x%x", uint32(res))
	}

	return nil
}

// DisableDnsLeakProtection removes the block rules added for DNS leak protection.
func DisableDnsLeakProtection(ctx context.Context) error {
	res := C.DeinitializeDnsLeakPreventer()
	if res != 0 {
		return fmt.Errorf("WFP DeinitializeDnsLeakPreventer failed with code: 0x%x", uint32(res))
	}
	return nil
}
