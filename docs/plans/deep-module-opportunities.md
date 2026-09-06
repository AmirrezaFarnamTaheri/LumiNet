# Deep-module opportunities

> **Historical planning snapshot.** This list predates the `src/` dependency-band refactor and the later deep-module/pruning passes. It is retained as design history, not as the current package map. Current ownership is defined by `repository-layout.md`, local `.context` files, and accepted ADRs.

The goal is not more folders. It is more behavior behind smaller interfaces, with callers and tests crossing the same seam.

## 1. Proxy runtime

**Cluster:** lifecycle, configuration, listener ownership, reload, shutdown, metrics, and status inside `server/internal/proxy`.  
**Pressure:** callers must understand many internal types and files; runtime state has broad ownership.  
**Target seam:** a `Runtime` module with a small interface such as `Start`, `Apply`, `Snapshot`, and `Close`.  
**Depth gained:** transport assembly, rollback, listener replacement, metrics, and state synchronization stay implementation details.  
**Proof:** boundary tests exercise configuration transitions, failed apply rollback, idempotent close, and status truth.

## 2. Transport registry

**Cluster:** protocol-specific constructors and compatibility aliases in the proxy package.  
**Target seam:** parse a validated transport specification and return one runtime adapter.  
**Rule:** introduce a seam only for two or more real adapters; do not add pass-through factories.  
**Proof:** table-driven contract tests across supported adapters and explicit unsupported-capability cases.

## 3. Scanner orchestration

**Cluster:** scanner scheduling, probes, reporting, cancellation, and persistence spread across server packages.  
**Target seam:** a scan session module returning immutable progress snapshots and a result.  
**Depth gained:** concurrency limits, retries, backpressure, and reporter fan-out remain internal.

## 4. Native core FFI

**Cluster:** `core/src/ffi/exports.rs`, envelope/version/allocation modules, and CGO bridge callers.  
**Target seam:** one versioned request/response envelope plus explicit allocation/free ownership.  
**Proof:** ABI layout tests, version mismatch, panic containment, allocation lifecycle, and package-load smoke tests.

## 5. Android platform owner

**Cluster:** VPN services, connectivity monitoring, profile parsing, and scan management formerly spread across `client/`, `desktop/`, and `server/`.  
**Target seam:** `mobile/android` is the platform module; Go mobile bindings remain in `server/internal/mobilebind`.  
**Proof:** manifest validation, coroutine/lifecycle tests, VPN permission flow, foreground-service behavior, and binding smoke tests.

## 6. Desktop control transport

**Cluster:** Wails bridge, HTTP diagnostic gateway, frontend `ControlTransport`, telemetry, and Zustand state.  
**Target seam:** one typed control client that owns authentication, request limits, decoding, and error translation.  
**Proof:** contract fixtures shared between Go and TypeScript, plus frontend state tests around unavailable/degraded/available outcomes.

## Sequence

1. Establish characterization tests at existing public seams.
2. Deepen one cluster at a time; do not rename public wire contracts in the same step.
3. Replace internal tests with boundary tests only after parity is demonstrated.
4. Remove compatibility aliases after one release cycle and usage evidence.
