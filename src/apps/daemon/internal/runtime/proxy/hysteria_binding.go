// Hysteria cgo compatibility exports.
//
// LumiNet does not embed a production Hysteria client runtime. Keep the native
// symbols for ABI compatibility, but fail closed instead of starting a mock
// loop or dialing destinations directly outside a Hysteria tunnel.
package proxy

/*
#include <stdlib.h>
typedef void (*LogCallback)(const char*);
*/
import "C"

import "unsafe"

//go:register Hysteria2_Start
//export Hysteria2_Start
func Hysteria2_Start(cAddr *C.char, cAuth *C.char, up int, down int) C.int {
	_ = cAddr
	_ = cAuth
	_ = up
	_ = down
	return -1
}

//export Hysteria2_RegisterLogger
func Hysteria2_RegisterLogger(cb unsafe.Pointer) {
	// No embedded Hysteria runtime exists, so there is no logger to register.
	_ = cb
}
