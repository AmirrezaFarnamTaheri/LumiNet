package plugins

import (
	"context"
	_ "embed"
	"testing"
)

//go:embed testdata/wasm_test.wasm
var testWasm []byte

func TestWasmRoutingPlugin(t *testing.T) {
	ctx := context.Background()

	plugin, err := LoadPlugin(ctx, testWasm)
	if err != nil {
		t.Fatalf("failed to load wasm plugin: %v", err)
	}
	defer plugin.Close(ctx)

	originalPacket := []byte{10, 20, 30, 40}
	action, mutated, err := plugin.EvaluateRoute(ctx, originalPacket)
	if err != nil {
		t.Fatalf("EvaluateRoute failed: %v", err)
	}

	// The wasm guest we compiled does the following:
	// - hostGetPacketSize() -> 4
	// - hostReadPacket(ptr, 4)
	// - Adds 1 to each byte -> {11, 21, 31, 41}
	// - hostWritePacket(ptr, 4)
	// - Returns action 2 (redirect)
	if action != 2 {
		t.Errorf("expected action 2, got %d", action)
	}

	expectedMutated := []byte{11, 21, 31, 41}
	if len(mutated) != len(expectedMutated) {
		t.Fatalf("mutated length mismatch: got %v, expected %v", mutated, expectedMutated)
	}

	for i := range expectedMutated {
		if mutated[i] != expectedMutated[i] {
			t.Errorf("byte mismatch at index %d: got %d, expected %d", i, mutated[i], expectedMutated[i])
		}
	}
}
