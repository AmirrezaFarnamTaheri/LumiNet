//go:build cgo && !android && !ios

package bridge

import (
	"strings"
	"testing"
)

func TestDisassemblePayload(t *testing.T) {
	// 6 NOPs: x86 NOP sled
	code := []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90}
	res, err := DisassemblePayload(code, "x64")
	if err != nil {
		t.Fatalf("DisassemblePayload failed: %v", err)
	}

	if !strings.Contains(res, "nop") {
		t.Errorf("Expected disassembly to contain 'nop', got: %s", res)
	}

	if !strings.Contains(res, "WARNING: Suspected NOP sled") {
		t.Errorf("Expected warning for NOP sled, got: %s", res)
	}
}
