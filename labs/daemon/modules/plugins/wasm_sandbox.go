package plugins

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

type contextKey string

const packetKey contextKey = "packet"

type PacketContext struct {
	Data []byte
}

type WasmRoutingPlugin struct {
	runtime wazero.Runtime
	mod     api.Module
}

func LoadPlugin(ctx context.Context, wasmBytes []byte) (*WasmRoutingPlugin, error) {
	r := wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)

	envBuilder := r.NewHostModuleBuilder("env")

	envBuilder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module) uint32 {
			pkt, ok := ctx.Value(packetKey).(*PacketContext)
			if !ok || pkt == nil {
				return 0
			}
			return uint32(len(pkt.Data))
		}).
		Export("host_get_packet_size")

	envBuilder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, ptr, maxLen uint32) uint32 {
			pkt, ok := ctx.Value(packetKey).(*PacketContext)
			if !ok || pkt == nil {
				return 0
			}
			size := uint32(len(pkt.Data))
			if size > maxLen {
				size = maxLen
			}
			if size > 0 {
				if !m.Memory().Write(ptr, pkt.Data[:size]) {
					return 0
				}
			}
			return size
		}).
		Export("host_read_packet")

	envBuilder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, ptr, length uint32) uint32 {
			pkt, ok := ctx.Value(packetKey).(*PacketContext)
			if !ok || pkt == nil {
				return 0
			}
			bytes, ok := m.Memory().Read(ptr, length)
			if !ok {
				return 0
			}
			mutated := make([]byte, len(bytes))
			copy(mutated, bytes)
			pkt.Data = mutated
			return 1
		}).
		Export("host_write_packet")

	envBuilder.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, ptr, length uint32) {
			bytes, ok := m.Memory().Read(ptr, length)
			if !ok {
				return
			}
			fmt.Printf("[WASM GUEST] %s\n", string(bytes))
		}).
		Export("host_log")

	_, err := envBuilder.Instantiate(ctx)
	if err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("failed to instantiate host module env: %w", err)
	}

	config := wazero.NewModuleConfig().
		WithSysNanosleep().WithSysWalltime().WithSysNanotime()
	// Explicitly omit WithFS and WithEnv — zero filesystem and env access
	mod, err := r.InstantiateWithConfig(ctx, wasmBytes, config)
	if err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("wasm sandbox init failed: %w", err)
	}
	evalFn := mod.ExportedFunction("evaluate_route")
	if evalFn == nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("wasm module missing evaluate_route export")
	}
	return &WasmRoutingPlugin{runtime: r, mod: mod}, nil
}

func (p *WasmRoutingPlugin) EvaluateRoute(ctx context.Context, packet []byte) (uint32, []byte, error) {
	pkt := &PacketContext{Data: packet}
	runCtx := context.WithValue(ctx, packetKey, pkt)

	evalFn := p.mod.ExportedFunction("evaluate_route")
	if evalFn == nil {
		return 0, packet, fmt.Errorf("evaluate_route function not exported")
	}

	results, err := evalFn.Call(runCtx)
	if err != nil {
		return 0, packet, fmt.Errorf("wasm evaluate_route call failed: %w", err)
	}

	var action uint32
	if len(results) > 0 {
		action = uint32(results[0])
	}
	return action, pkt.Data, nil
}

func (p *WasmRoutingPlugin) Close(ctx context.Context) error {
	return p.runtime.Close(ctx)
}
