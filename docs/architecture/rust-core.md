# 🦀 Rust Core Architecture & Technical Manual

This document provides a technical guide to the performance-critical scanning and diagnostic core located under `src/packages/lumicore/`. It details module structures, memory boundaries, threading models, and low-level evasion algorithms.

---

## 1. Directory & Module Mapping

`src/packages/lumicore/` is the live Rust crate. Source-purity validation requires every Rust file under `src/` to be reachable from the crate graph; unreachable/foreign alternates are preserved under `labs/lumicore/`.

Key live FFI files are:

```text
src/packages/lumicore/src/ffi/
├── envelope.rs       # ABI version, FfiEnvelope/FfiStatus, status codes
├── binary_bridge.rs  # lumicore_call dispatcher
├── binary_scan.rs    # Rust-internal packed scan payload/result types
├── streaming.rs      # StreamHandle and cancellable callback stream
├── version.rs        # ABI version negotiation/string
├── async_exports.rs  # retained callback-based compatibility entry point
├── exports.rs        # retained JSON/string compatibility exports
└── mod.rs            # FFI helpers and Rust-owned allocation/free exports
```

The repository does not generate an active root C header. The Go host declaration surface is checked in at `src/apps/daemon/internal/native/bridge/lumicore_abi.h`; the former cbindgen configuration/generated header are reference-only under `governance/reference/ffi/`.

---

## 2. Go-Rust FFI Interface Boundary

The host Go bridge has one C declaration authority: `lumicore_abi.h`. `scripts/checks/check_lumicore_abi.py` compares it with live Rust and enforces:

- ABI version equality;
- field/type parity for the Go-visible `FfiEnvelope`, `FfiStatus`, and `StreamHandle`;
- declarations for every Rust export actually called by Go and no unused Rust declarations;
- no inline Rust prototype lists in individual CGO source files;
- equality of the four stream-event numeric constants across Rust and the private C header.

The active product bridge uses the versioned generic `lumicore_call` interface plus retained version/JSON/string compatibility exports used by `core.go`. The Rust ABI still retains the streaming symbols and their ownership protocol, but the repository has no production caller of Go `StartStream` and the current scan stream body is a stub; streaming is therefore **not** an advertised production scan capability. Removal or implementation is gated on the pinned Cargo fmt/Clippy/test plus ABI/CGO verification lane recorded in `governance/topology/wave17-native-reachability.json`. The unused specialized `ExecScan -> lumicore_scan_execution` mock path was retired because it fabricated successful scan results; its historical Go and Rust implementations are preserved under `labs/*/ffi-alternates/`. Rust-owned legacy strings are copied into Go and released through Rust's `free_string`. Binary calls use caller-owned buffers and structured `FfiStatus` results.

Cargo is the native-link authority. `scripts/checks/lumicore_link.py` resolves the built static archive and parses Cargo's `native-static-libs` output for the selected profile/target; Go source does not hard-code platform link libraries or archive directories.

---

## 3. Runtime & Streaming Lifetime Model

`src/packages/lumicore/src/runtime.rs` owns the shared host-FFI Tokio runtime through a fallible `OnceLock<Result<Runtime, String>>`. Runtime initialization failure is retained and returned on every later access instead of panicking from an `extern "C"` path. Tokio-based compatibility exports and `ffi/streaming.rs` use this shared runtime. Compio operations keep a separate thread-local Compio executor because they use a different runtime model; its initialization is also fallible. The target-specific iOS FFI contains a purpose-specific two-worker Tokio runtime when built, but no current shipped iOS host or release lane consumes it.

The retained streaming ABI has an explicit ownership protocol even though no product caller currently uses it. A failed runtime start or invalid input returns the existing zero `StreamHandle` sentinel and schedules no callback. A successful stream keeps its `CancellationToken` in Rust until the runtime task finishes. `lumicore_stream_cancel` only signals cancellation; it does not remove stream ownership. Rust catches stream-task unwind, reports an error event, removes the stream from its live map, and then emits exactly one terminal `STREAM_EVT_SCAN_DONE` callback. The dormant Go bridge keeps callback memory and its channel alive until that terminal callback, which removes the sink, closes the channel, and frees the C callback context. This ordering prevents cancellation from freeing `user_data` while a late callback is still possible.

The retained ADB-forwarder compatibility export still creates a purpose-owned Tokio runtime on a detached thread and has no current product caller. It is not part of the streaming lifetime contract and should be evaluated independently before promotion or reuse.

---

## 4. Low-Level Evasion Algorithms

### 4.1 Stateless Scanning via Blackrock Shuffling
To scan large networks without saturating target subnets or consuming excessive memory, the ICMP sweep engine implements the **Blackrock index shuffling algorithm**:
* **Mathematical Permutation:** Shuffles the range of target IP indices using a key-based pseudo-random block cipher permutation.
* **Stateless Execution:** Maps each index `i` (from `0` to `N-1`) to a unique shuffled address `f(i)` deterministically. This allows millions of hosts to be scanned in a random order without maintaining a list of visited addresses in memory.
* **IDS Evasion:** Distributes target addresses pseudo-randomly over time, preventing local intrusion detection systems (IDS) from triggering on sequential IP range scans.

### 4.2 Padded WireGuard Probes
Standard WireGuard handshakes use a fixed 148-byte UDP packet, which is easily blocked by length-matching DPI systems. The WireGuard auditor (`src/packages/lumicore/src/wg/prober.rs`) implements configurable UDP padding:
* **Variable Payload Size:** Appends randomized padding bytes to the WireGuard Handshake Initiation packet, changing its length signature (e.g. up to 512+ bytes).
* **Evasion Auditing:** Probes target endpoints with padded vs. standard handshakes to determine if the local ISP blocks connections based on fixed packet lengths.

### 4.3 Encrypted Client Hello (ECH) Parser
The DNS subsystem implements HTTPS (Type 65) resource record checks to detect Encrypted Client Hello configurations:
* Query target domains for Type 65 HTTPS resource records.
* Parse the raw record payload to identify the presence of the `ech` parameter.
* If ECH blocks are present, the engine checks whether local UDP DNS queries drop these records to verify DNS-level censorship policies.

---

## 5. Panic Safety Boundaries

Versioned binary calls use `ffi::envelope::guard_ffi` to convert Rust panics into `FFI_ERR_PANIC` rather than unwind through C. Retained legacy exports have their own panic/error handling and must be reviewed individually when changed. New host bridge work should prefer the versioned status/envelope contract and must not allow unwinding across the ABI.

---

## 6. Raw Sockets Abstraction Layer

Raw socket configurations are abstracted behind the `Platform` trait to ensure cross-platform compatibility:

```rust
pub trait PlatformSocket {
    fn create_raw_icmp_socket() -> Result<RawSocketDescriptor, SocketError>;
    fn set_socket_timeouts(fd: RawSocketDescriptor, timeout: Duration) -> Result<(), SocketError>;
    fn receive_packet(fd: RawSocketDescriptor, buffer: &mut [u8]) -> Result<usize, SocketError>;
}
```

* **Windows:** Winsock2 implementation utilizing `SOCK_RAW` for ICMP sweeps.
* **Linux:** Uses standard raw socket interfaces with `CAP_NET_RAW` capability rules.
