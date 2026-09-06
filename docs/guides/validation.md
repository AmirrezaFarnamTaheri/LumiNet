# 🧪 LumiNet Verification, Validation & Audit Plan

This document details the performance, reliability, and security validation suites, testing harness parameters, and validation checklists for the LumiNet platform.

---

## 1. Validation Methodologies

LumiNet validates cross-runtime memory operations, OS network state changes, and cryptographic operations through isolated unit testing and target mock controllers.

### 1.1 Performance Validation
* **JSON FFI vs. Binary FFI Benchmarking:**
  * Runs concurrent Sweeps targeting `/16` network sizes.
  * Measures FFI payload overhead, CPU time, stack size, and allocation rates.
  * Ensures garbage collector overhead is minimal by avoiding JSON-string allocations on hot path bindings.
* **Radix Trie Domain Match Lookup Benchmarking:**
  * Compares Go linear domain sweeps with Rust-compiled radix trie lookups.
  * Validates search speed on lists containing 10,000+ domain routing entries.
* **TCP Output Ring Buffering:**
  * Benchmarks raw packet processing speeds on standard TUN/TAP interfaces.
  * Measures packet dropping counts and memory throughput.

### 1.2 Reliability Validation
* **Watchdog Process Crash Rollbacks:**
  * Induces hard crashes (e.g. `SIGKILL`) on the main `luminet` process while system DNS settings, proxy configurations, or NCSI overrides are active.
  * Asserts that the standby watchdog process detects the lock state file `watchdog_state.lock` missing, invalidates modifications, and restores original configurations within 2 seconds.
* **WFP Session Auto-Cleanup:**
  * Validates that all active Windows Filtering Platform (WFP) sessions are registered using `FWPM_SESSION_FLAG_DYNAMIC`.
  * Verifies that if the process exits normally or abnormally, Windows automatically drops all dynamic filters from the kernel engine.
* **Go Race Detection:**
  * Runs Go test runs under the `-race` detector flags during concurrent configuration reloads and active proxy benchmark queries.

### 1.3 Security Validation
* **Log Redaction Audits:**
  * Injects known sensitive credential pattern types (`Bearer token`, `vless://`, `trojan://`, `api_key=secret`) into logger payloads.
  * Asserts that output log files contain only filtered symbols (`***`), blocking credentials from logs.
* **Local Privilege Gating:**
  * Asserts that local endpoints (REST/WebSockets) reject unauthenticated requests.
  * Verifies that the Local IPC (Named Pipes/UDS) verifies caller permissions before executing system adjustments.

---

## 2. Validation Track Checklist

Verify the following release checklists on the target machine:

### 2.1 Repository & Build Graph Purity
- [x] **No Tracked Binary Drivers:** Verifies that `.sys`, `.dll`, `.syso`, or `.exe` files do not exist in the source index.
- [x] **No Misplaced Workspaces:** Verifies that no nested cargo workspace folders (e.g. `scratch_tuic`) remain inside `src/apps/daemon/`.
- [x] **Reproducible Lockfiles:** Verifies that `src/packages/lumicore/Cargo.lock` is committed, matching build dependencies.
- [x] **Repository Tooling Authority:** CI compiles/tests `scripts/internal/...` and `scripts/cmd/...`; validator modules resolve canonical governance/ABI files from repository root so workflow callers cannot mask stale authority paths.
- [x] **Control UI Package Manager:** Node 22.16.0 and its bundled npm 10.9.2 are the exact control-UI toolchain; `package.json` declares `npm@10.9.2`, build/development launchers use npm consistently with the checked lockfile, and the release audit covers dev/build dependencies before executing them.
- [x] **Pinned Release Toolchains:** Rust is fixed at 1.97.1 in `rust-toolchain.toml` and every Rust workflow setup block; CI/release use Node 22.16.0 and explicit Ubuntu 24.04 / Windows 2025 / macOS 15 runner families rather than moving major aliases.
- [x] **Repository Tooling Surface:** `scripts/checks/check_tooling_surface.py` requires every top-level executable tool to be either a documented direct interface or a live-called internal helper, and keeps retired one-off/fetch/installer surfaces absent. CI and tag publication reach `make verify-repo`, preservation validation, and dependency-security audits through the canonical `make verify-release` admission interface, so critical gates cannot be masked by handwritten workflow subsets.
- [x] **Windows Raw-Packet Dependency Truth:** WinDivert is operator-supplied and not bundled; unsafe repository fetch/Scoop surfaces remain retired, and evasion startup fails closed when the requested Windows packet injector cannot load its dependency.

### 2.2 System & DNS Mutation Safety
- [x] **Native Windows API Mappings:** Verifies that DNS overrides utilize native `iphlpapi` DLL helper calls instead of spawning slow, fragile PowerShell subprocesses.
- [x] **Watchdog Hooking:** Verifies that starting the server daemon boots the watchdog runner, writing status to the state folder.
- [x] **Registry Backups:** Verifies that system overrides backup registry values to SQLite before applying alterations.

### 2.3 API & Local Control Gating
- [x] **Auth Token Enforcement:** Verifies that the API gateway blocks requests without valid token headers.
- [x] **Local IPC Handshake:** Verifies that Named Pipes and Unix Domain Sockets authorize caller access before exposing capabilities.
- [x] **JSON log redaction:** Verifies that sensitive query properties are automatically filtered before serialization to console standard outputs.

### 2.4 Data Store Resilience
- [x] **Foreign Keys Active:** Verifies that the SQLite database logs `foreign_keys=ON` during initialization.
- [x] **WAL Mode Applied:** Verifies that the database pool starts in Write-Ahead Logging (WAL) mode for safe multi-threaded concurrency.
- [x] **Versioned migrations:** Verifies that database updates are applied sequentially and audited inside the `schema_migrations` table.
- [x] **Historical covert-visit migrations retained (15-21):** the old schema steps remain append-only so existing databases can migrate deterministically. Covert tracking/shortlink routes and their live retention/shortlink implementations are retired; migration history is not runtime capability.

---

## 3. Platform Stub Status (Post-Implementation Audit)

The following stubs were audited and resolved as of 2026-06-25:

| Item | File | Status | Notes |
|------|------|--------|-------|
| Prometheus metrics endpoint | `src/apps/daemon/internal/adapters/api/routes_misc.go` | ✅ **Fail-closed** | No production metrics pipeline is initialized; `/api/metrics` returns 501 instead of exposing an empty registry. |
| Leak protection (Linux) | `src/apps/daemon/internal/platform/system/firewall_unix.go` | ✅ **Implemented** | `iptables` chain `LUMINET_LEAK` + IPv6 drop |
| Leak protection (macOS) | `src/apps/daemon/internal/platform/system/firewall_unix.go` | ✅ **Implemented** | `pfctl` anchors `luminet-leak` / `luminet-dnsleak` |
| Auto-start (Linux) | `src/apps/daemon/internal/platform/process/startup_unix.go` | ✅ **Implemented** | systemd user service unit |
| Auto-start (macOS) | `src/apps/daemon/internal/platform/process/startup_unix.go` | ✅ **Implemented** | LaunchAgent plist |
| DDNS providers | `src/apps/daemon/internal/networking/dns/ddns_updater.go` | ✅ **Implemented** | Cloudflare, DuckDNS, No-IP, Dynu |
| Desktop notifications | `src/apps/daemon/internal/integrations/notifier/notifier.go` | ✅ **Implemented** | Windows Toast, macOS osascript, Linux notify-send |
| Subscription CAPTCHA solver | `src/apps/daemon/internal/integrations/captchaclient/solver.go` | ✅ **Implemented** | Active HTTP solver used by subscription flows; the separate build-tagged `internal/captcha` experiment is preserved under `labs/daemon/modules/` and is not shipped. |
| Mobile ProtectSocket callback | `src/apps/daemon/internal/platform/mobilehost/host.go` | ✅ **Implemented** | gomobile registers the host callback; protected dialers share this one platform seam. |
| FFI envelope fuzz test | `src/apps/daemon/internal/native/bridge/fuzz_test.go` | ✅ **Fixed** | Envelope size corrected to 40 bytes (2+2+4+8+8+8+8) |
| NCSI stubs | `src/apps/daemon/internal/platform/system/ncsi_unix.go` | ✅ **Correct by design** | NCSI is Windows-only; stubs return sensible no-op defaults |
| Historical MITM fronting adapter | `labs/daemon/modules/mitm/mitm_fronting.go` | ✅ **Preserved, non-product** | Historical implementation remains under governed labs and is not active capability. |
| Legacy Windows Service-on-Unix stub | — | ✅ **Retired** | No active product path requires a Unix compatibility implementation of Windows Service Manager. |
| Named Pipes on non-Windows | `src/apps/daemon/internal/adapters/api/ipc_listener_other.go` | ✅ **Correct by design** | Named Pipes are Windows-only |
| Legacy TCP Brutal tuning family | — | ✅ **Retired** | Product-unconsumed wrapper and Linux/stub variants were removed after liveness proof; no active capability advertises them. |


## Telemetry truth guard

`PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_telemetry_truth.py` verifies that live WebSocket metrics come from canonical traffic counters, unknown latency remains nullable, dead diagnostic-log state does not reappear, one JSON envelope is sent per WebSocket frame, and the retired standalone telemetry server remains outside active source.
## Rust FFI runtime safety guard

`PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_ffi_runtime_safety.py` verifies that the shared host Tokio runtime is fallible, retained compatibility executors do not panic on initialization, iOS session locking fails through its ABI-safe return contract, stream startup uses the zero-handle failure sentinel, cancellation does not release callback ownership early, stream-task panic still reaches terminal cleanup, and Go frees callback context only from the terminal callback. `scripts/checks/check_lumicore_abi.py` additionally verifies the `StreamHandle` layout and stream-event values against the private C header. Native Rust format/Clippy/test execution remains the stronger CI layer when Cargo is available.
## FFI dormant-surface guard

`PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_ffi_dead_surface.py` verifies that the unused specialized `ExecScan -> lumicore_scan_execution` mock is absent from the active Go/Rust/private-header interface, its historical implementations remain preserved under governed labs, Rust-internal packed scan types are not leaked into the Go host header, and the canonical generic `lumicore_call` seam remains present on both sides.

## Post-convergence ownership and pruning guards

- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_request_context.py` requires HTTP handlers and Doctor readiness checks to propagate caller context and rejects detached handler goroutines/background contexts.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_subscription_ownership.py` and `check_subscription_pruning.py` enforce one `internal/integrations/sub` ingestion/refresh owner and forbid retired parser/aggregator trees.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_advanced_capability_truth.py` and `check_advanced_runtime_pruning.py` enforce explicit truth for the 20 advanced system registrations and prevent disconnected runtime owners from returning.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_route_truth.py` verifies that `/api/routes` derives existence from the live Gin router and that retired covert/extension/orphan surfaces stay absent.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_proxy_liveness.py` and `check_final_pruning.py` keep proven-unconsumed internal source retired while retaining cgo/JNI/build-tag stop conditions and historical migrations.
- `PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/check_runtime_core_ownership.py` keeps Tor/Psiphon implementation locality under `internal/runtime/runtimecore` and keeps Xray/sing-box qualification separate.
