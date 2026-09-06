//go:build cgo && !android && !ios

package bridge

// #include "lumicore_abi.h"
import "C"
import (
	"fmt"

	"errors"
	"unsafe"
)

var ErrBufTooSmall = errors.New("bridge: output buffer too small")

const ABIVersion = 3

// Op codes matching OpCode in envelope.rs
const (
	OpScan        uint16 = 1
	OpRouteUpdate uint16 = 2
	OpEchGrease   uint16 = 3
	OpTlsFragment uint16 = 4
	OpPoolRefresh uint16 = 5
	OpSniRotate   uint16 = 6
)

// Flags for FfiEnvelope.flags
const (
	FlagCompress uint32 = 0x01
	FlagEncrypt  uint32 = 0x02
	FlagStream   uint32 = 0x04
)

// TraceID is a 128-bit distributed trace identifier.
type TraceID struct{ Hi, Lo uint64 }
type traceIDKey struct{}

// PanicError is returned when the Rust handler panicked.
type PanicError struct {
	Msg string
	Op  uint16
}

func (e *PanicError) Error() string {
	return fmt.Sprintf("rust panic in op=%d: %s", e.Op, e.Msg)
}

// sizeofFfiEnvelope is derived from the C declaration so the Go bridge tracks
// Rust's usize-based ABI on every supported architecture.
var sizeofFfiEnvelope = int(unsafe.Sizeof(C.FfiEnvelope{}))

// marshalEnvelope copies an envelope into the first native C envelope bytes of buf.
func marshalEnvelope(env C.FfiEnvelope, buf []byte) error {
	if len(buf) < sizeofFfiEnvelope {
		return ErrBufTooSmall
	}
	*(*C.FfiEnvelope)(unsafe.Pointer(&buf[0])) = env
	return nil
}
