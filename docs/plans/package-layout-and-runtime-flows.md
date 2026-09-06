# 📂 LumiNet Package Layout & Runtime Flows Specification

> **Historical target specification.** This document preserves an earlier target package/runtime model. It is design history, not current source/capability truth. Use `../architecture/overview.md`, `../architecture/repository-layout.md`, and local `.context` files for the current system.


This document details the target package layout, system boot sequences, job state flows, transactional host mutations, and OS-specific platform adapters.

---

## 1. System Component Registry

LumiNet's modular structure separates Rust data-plane execution from Go orchestration and lifecycle management.

| Component | Language | Responsibility | Key Interfaces |
|---|---|---|---|
| `lumicore` packet engine | Rust | Scanning, probing, zero-copy packet processing, compiled routing, virtual interface rings | Packed FFI, memory-mapped buffers, status codes, callback context |
| `DaemonOrchestrator` | Go | Lifecycle, dependency wiring, service startup/shutdown, watchdog registration | Local IPC, structured config, context cancellation |
| `EvasionConfigContext` | Go | Immutable, atomic configuration snapshots | `atomic.Pointer[EvasionConfig]`, validation pipeline |
| `TunnelListener` | Go | SOCKS5 and local proxy listener lifecycle | Context cancellation, listener interface |
| `DnsForwarder` | Go | DNS interception, forwarding, EWMA resolver selection | Platform adapter, resolver interface, EWMA tracker |
| `PlatformInterceptor` | Go | OS-specific tunnel, DNS, proxy, WFP/netlink/NetworkExtension/VpnService work | Native platform implementations behind build tags |
| `TelemetryBuffer` | Go | Fixed-capacity event ring, redacted log output | Ring mutex, `Since(seq)` replay, WebSocket/MCP output |
| `TrafficAccountant` | Go | Byte accounting, async database flush | Atomic counters, background persistence goroutine |
| `RouteEngine` | Rust | Domain, CIDR, GeoSite/GeoIP matching | Radix trie, Aho-Corasick, memory-mapped rule DB |
| `PluginRuntime` | Go | Community extensions | wazero sandbox, capability host functions, signed manifests |
| `LocalControl` | Go | CLI, MCP, UI, and automation control | JSON-RPC 2.0 stdio, gRPC UDS/named pipe, optional tokenized HTTP |
| `SystemTransactionMgr` | Go | DNS/proxy/WFP/NCSI snapshot, apply, verify, rollback | Snapshot store, rollback API, watchdog integration |
| `EvidenceStore` | Go | Per-probe result persistence, export, retention | SQLite WAL, typed repositories, export generators |
| `Scheduler` | Go | Job queues, worker pools, admission control, deadlines | `Submit()`, `Cancel()`, backpressure, metrics integration |
| `EventBus` | Go | Replayable event delivery to all subscribers | Ring buffer, `Since(seq)`, SQLite event log, WebSocket/SSE |
| `Watchdog` | Go | Crash rollback for network settings and CA | Parent-process monitoring, emergency rollback |
| `CapabilityRegistry` | Go | Feature maturity labeling, platform capability detection | Stable/beta/experimental/internal labels, `/api/capabilities` |

---

## 2. Codebase Directory Map

```text
LumiNet/
├── src/
│   ├── apps/
│   │   ├── daemon/             # Go daemon/CLI/watchdog and bridge entry points
│   │   ├── desktop/            # one Wails host package
│   │   └── mobile/android/     # canonical Android Activity + VpnService
│   └── packages/
│       ├── contracts/          # shared session discovery + build info
│       ├── control-ui/         # sole React source + production embed bundle
│       └── lumicore/           # reachable Rust native core
├── labs/                       # governed, hash-accounted non-authoritative alternates
├── deploy/                     # relay/runtime delivery, templates, packaging/bootstrap
├── governance/
│   ├── conductor/              # machine-facing current policy
│   ├── convergence/            # adoption/accountability/split-brain evidence
│   ├── reference/              # historical authorities, never live build owners
│   └── topology/               # 2,442-object baseline accounting
├── scripts/                    # build and verification tooling
└── tests/                      # cross-module integration/contract tests
```

The live host FFI declaration surface is `src/apps/daemon/internal/native/bridge/lumicore_abi.h`; the old cbindgen configuration/header are reference evidence. The supported desktop product owns no frontend subdirectory: both daemon and desktop consume `src/packages/control-ui`.

---

## 3. Runtime Flows Specification

### 3.1 Startup & Boot Orchestration Flow

```text
                  Start Application
                         │
                         ▼
             Read JSON configuration file
                         │
                         ▼
        Verify security properties (No empty API keys)
                         │
                         ▼
       Initialize logger and log-scrubbing redactor
                         │
                         ▼
    Open SQLite DB (Set WAL Mode & Run migrations)
                         │
                         ▼
          Initialize Capability Registry
                         │
                         ▼
         Initialize Job Scheduler & Event Bus
                         │
                         ▼
       Launch Watchdog daemon (Detach independent process)
                         │
                         ▼
     Bind Local IPC (UDS/Named Pipes) & HTTP Server
                         │
                         ▼
             Is GUI Console requested?
                     ├─── Yes ───► Boot Wails window
                     └─── No  ───► Run in headless mode
```

### 3.2 Asynchronous Job Execution Flow

This workflow illustrates how user jobs (e.g., active scanning sweeps) compile, run, stream live telemetry, and persist results:

```text
  [ User Client ]         [ Job Scheduler ]       [ Rust Core Engine ]       [ Evidence Store ]
         │                        │                        │                         │
         ├─── Submit Request ────►│                        │                         │
         │                        ├─── Queue Validation ──►│                         │
         │                        │    (Resource budgets)  │                         │
         │                        │                        │                         │
         │                        ├─── Launch Job ────────►│                         │
         │                        │    (With Context ID)   │                         │
         │                        │                        │                         │
         │                        │                        ├─── Probe Packets ──────►│
         │                        │                        │                         │
         │                        │◄── Stream FFI Result ──┤                         │
         │                        │    (Incremental callback)                        │
         │                        │                        │                         │
         │                        ├────────────────────────┼─── Stream Save ────────►│
         │                        │                        │    (Insert SQL row)     │
         │                        │                        │                         │
         │◄── WS Progress Frame ──┤                        │                         │
         │    (Live telemetry)    │                        │                         │
```

### 3.3 Transactional System Configuration Change Flow

OS configuration mutations (DNS changes, proxy parameters, NCSI overrides) are run via transactional boundaries with independent watchdog protection:

```text
[ System Config Subsystem ]     [ Win32/Platform Adapters ]     [ Watchdog Process ]
            │                               │                            │
            ├─── 1. Build Transition ──────►│                            │
            │                               │                            │
            ├─── 2. Take Snapshot ─────────►│                            │
            │    (Backup active settings)   │                            │
            │                               │                            │
            ├─── 3. Write State Cache ──────┼───────────────────────────►│
            │                               │   (Watchdog tracks lock)   │
            │                               │                            │
            ├─── 4. Apply Changes ─────────►│                            │
            │                               │                            │
            ├─── 5. Run Verification ──────►│                            │
            │    (Query consensus resolver) │                            │
            │                               │                            │
            ├─── 6. Commit / Success ───────┼───────────────────────────►│
            │                               │   (Release watchdog lock)  │
            │                               │                            │
            ▼                               ▼                            ▼
```

---

## 4. Platform Adaptation Matrix

LumiNet uses direct OS bindings rather than generic shells to ensure reliability, transaction rollbacks, and security compatibility.

| Platform | OS Network Interceptor | Local IPC Method | Target Packaging |
|---|---|---|---|
| **Windows** | Native Win32 (`iphlpapi.dll`), Wintun interfaces, dynamic WFP filtering sessions | Windows Named Pipes with Security Descriptors (SDDL) | Daemon/watchdog plus Wails desktop executables; no generated resources are written into live source |
| **Linux** | `netlink` sockets, `nftables` interface rules, user-space `AF_PACKET` rings | Unix Domain Sockets (0600 file permissions) | Packaged standard systemd daemon and CLI utility |
| **macOS** | macOS NetworkExtension APIs, native Keychain integration | Unix Domain Sockets (0600 file permissions) | Package App bundle with signed binary executables |
| **Android** | Standard Android `VpnService` adapter, JVM-to-Native socket file descriptor protection | Local standard Unix Domain Sockets | Target Android Application Package (APK) with FFI bindings |

Current mobile delivery is Android-only. iOS-specific source remains guarded/non-shipped and is tracked as future delivery work rather than a current platform target.
