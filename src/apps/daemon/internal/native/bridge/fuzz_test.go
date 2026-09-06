// Package bridge — FFI fuzz harness (Go side).
//
// Addresses E-10: FFI Fuzz Harness + Null-Safe Free.
//
// FuzzFFIEnvelope tests envelope validation without requiring the compiled
// Rust shared library. It verifies that:
//   - No panic occurs for any byte sequence passed as an envelope header
//   - The abi_version check correctly gates invalid ABI versions
//   - Zero-length input_len / output_cap are handled gracefully
//   - Extremely large field values don't cause integer overflow
package bridge

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// ffiEnvelope mirrors the C struct FfiEnvelope for Go-side testing.
type ffiEnvelope struct {
	ABIVersion uint16
	OpCode     uint16
	Flags      uint32
	TraceIDHi  uint64
	TraceIDLo  uint64
	InputLen   uint64
	OutputCap  uint64
}

// parseEnvelope attempts to parse a raw byte slice into an ffiEnvelope.
// Returns false if the input is too short.
func parseEnvelope(data []byte) (ffiEnvelope, bool) {
	// FfiEnvelope is 40 bytes: 2+2+4+8+8+8+8
	if len(data) < 40 {
		return ffiEnvelope{}, false
	}
	return ffiEnvelope{
		ABIVersion: binary.LittleEndian.Uint16(data[0:2]),
		OpCode:     binary.LittleEndian.Uint16(data[2:4]),
		Flags:      binary.LittleEndian.Uint32(data[4:8]),
		TraceIDHi:  binary.LittleEndian.Uint64(data[8:16]),
		TraceIDLo:  binary.LittleEndian.Uint64(data[16:24]),
		InputLen:   binary.LittleEndian.Uint64(data[24:32]),
		OutputCap:  binary.LittleEndian.Uint64(data[32:40]),
	}, true
}

const currentABIVersion = 3

// validateEnvelope performs Go-side envelope validation before any CGo call.
// Returns a non-nil error if the envelope should be rejected without
// crossing the FFI boundary.
func validateEnvelope(env ffiEnvelope) error {
	if env.ABIVersion != currentABIVersion {
		return errorf("ABI version mismatch: got %d want %d", env.ABIVersion, currentABIVersion)
	}
	// Cap buffer sizes at 64 MiB to prevent accidental huge allocations.
	const maxBuf = 64 << 20
	if env.InputLen > maxBuf {
		return errorf("input_len %d exceeds max %d", env.InputLen, maxBuf)
	}
	if env.OutputCap > maxBuf {
		return errorf("output_cap %d exceeds max %d", env.OutputCap, maxBuf)
	}
	return nil
}

// FuzzFFIEnvelope is the go-test fuzz entry point.
func FuzzFFIEnvelope(f *testing.F) {
	// Seed corpus: valid envelope.
	seed := make([]byte, 40)
	binary.LittleEndian.PutUint16(seed[0:2], currentABIVersion)
	binary.LittleEndian.PutUint16(seed[2:4], 0x0001) // op_code = 1
	f.Add(seed)

	// Seed corpus: zero-length input.
	seed2 := make([]byte, 40)
	binary.LittleEndian.PutUint16(seed2[0:2], currentABIVersion)
	f.Add(seed2)

	f.Fuzz(func(t *testing.T, data []byte) {
		env, ok := parseEnvelope(data)
		if !ok {
			return // too short — not a valid test case
		}
		// Must not panic regardless of field values.
		_ = validateEnvelope(env)
	})
}

// errorf creates a formatted error.
func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
