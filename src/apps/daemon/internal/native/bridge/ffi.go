//go:build cgo && !android && !ios

package bridge

// #include "lumicore_abi.h"
import "C"
import (
	"context"
	"fmt"
	"unsafe"
)

const maxOutputBuf = 4 * 1024 * 1024 // 4 MiB per-call maximum

// Call dispatches a single synchronous FFI operation.
// op: one of Op* constants; payload: operation-specific binary payload.
// Returns output bytes on FFI_OK; error otherwise.
func Call(ctx context.Context, op uint16, payload []byte) ([]byte, error) {
	env := C.FfiEnvelope{
		abi_version: C.uint16_t(ABIVersion),
		op_code:     C.uint16_t(op),
		input_len:   C.size_t(len(payload)),
		output_cap:  C.size_t(maxOutputBuf),
	}
	if tid, ok := ctx.Value(traceIDKey{}).(TraceID); ok {
		env.trace_id_hi = C.uint64_t(tid.Hi)
		env.trace_id_lo = C.uint64_t(tid.Lo)
	}

	outBuf := make([]byte, maxOutputBuf)
	var inputPtr *C.uint8_t
	if len(payload) > 0 {
		inputPtr = (*C.uint8_t)(unsafe.Pointer(&payload[0]))
	}

	status := C.lumicore_call(&env, inputPtr, (*C.uint8_t)(unsafe.Pointer(&outBuf[0])))

	// Detect verbose panic info
	if status.code == C.int32_t(FFI_ERR_PANIC) && int(status.output_len) >= 4 {
		if string(outBuf[:4]) == "PNIC" {
			msg := string(outBuf[4:int(status.output_len)])
			return nil, &PanicError{Msg: msg, Op: op}
		}
	}
	if status.code != 0 {
		return nil, fmt.Errorf("lumicore_call op=%d code=%d errcode=%d",
			op, int(status.code), int(status.error_code))
	}
	return outBuf[:int(status.output_len)], nil
}

const (
	FFI_OK           = 0
	FFI_ERR_NULL     = -1
	FFI_ERR_PANIC    = -2
	FFI_ERR_ABI      = -3
	FFI_ERR_CAPACITY = -4
	FFI_ERR_DECODE   = -5
)
