// Ported from: wazero-meta-v1.11.0
// Target path: server/internal/plugins/wazero_loader.go

package plugins

import (
	"context"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// WazeroPluginHost runs sandboxed WASM plugins inside the LumiNet Go backend.
type WazeroPluginHost struct {
	runtime wazero.Runtime
	ctx     context.Context
}

// NewWazeroPluginHost initializes a new wazero runtime environment.
func NewWazeroPluginHost(ctx context.Context) *WazeroPluginHost {
	return &WazeroPluginHost{
		runtime: wazero.NewRuntime(ctx),
		ctx:     ctx,
	}
}

// LoadAndRunWasm compiles and instantiates a WASM plugin, executing the exported function.
func (h *WazeroPluginHost) LoadAndRunWasm(wasmPath string, exportName string, input []byte) ([]byte, error) {
	wasmBytes, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, fmt.Errorf("wazero_loader: read file: %w", err)
	}

	// Instantiate WASI preview1 dependencies
	_, err = wasi_snapshot_preview1.Instantiate(h.ctx, h.runtime)
	if err != nil {
		return nil, fmt.Errorf("wazero_loader: instantiate WASI: %w", err)
	}

	// Instantiate the user plugin module
	mod, err := h.runtime.Instantiate(h.ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("wazero_loader: instantiate plugin: %w", err)
	}
	defer mod.Close(h.ctx)

	// Fetch the exported function
	runFunc := mod.ExportedFunction(exportName)
	if runFunc == nil {
		return nil, fmt.Errorf("wazero_loader: exported function %q not found", exportName)
	}

	// Simple execution logic. For plugins, we often write the input payload into
	// a shared memory block inside the WASM module. For this generic FFI loader,
	// we invoke the function directly.
	results, err := runFunc.Call(h.ctx)
	if err != nil {
		return nil, fmt.Errorf("wazero_loader: call exported function: %w", err)
	}

	return []byte(fmt.Sprintf("%v", results)), nil
}

// Close releases the wazero runtime and compiled modules.
func (h *WazeroPluginHost) Close() error {
	return h.runtime.Close(h.ctx)
}
