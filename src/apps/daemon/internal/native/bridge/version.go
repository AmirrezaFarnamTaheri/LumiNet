//go:build cgo && !android && !ios

package bridge

// #include "lumicore_abi.h"
import "C"
import "fmt"

const RequiredABIMajor = 3

// NegotiateVersion verifies the loaded lumicore library matches the required ABI.
// Call once at process startup before any bridge.Call().
func NegotiateVersion() (string, error) {
	packed := uint64(C.lumicore_version(C.uint16_t(RequiredABIMajor)))
	if packed == 0 {
		return "", fmt.Errorf("lumicore ABI incompatible: binary requires major=%d", RequiredABIMajor)
	}
	major := uint16((packed >> 32) & 0xFFFF)
	minor := uint16((packed >> 16) & 0xFFFF)
	patch := uint16(packed & 0xFFFF)
	buf := make([]byte, 64)
	n := int(C.lumicore_version_string((*C.uint8_t)(&buf[0]), C.size_t(len(buf))))
	libStr := string(buf[:n])
	return fmt.Sprintf("v%d.%d.%d (%s)", major, minor, patch, libStr), nil
}
