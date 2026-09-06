# LumiNet Developer Onboarding Guide

Welcome to the **LumiNet** codebase. This guide provides a rapid, structured introduction to the architecture, core execution layers, conventions, and operational workflows needed to develop, test, and contribute to the platform.

---

## 1. System Overview

LumiNet is a high-performance, censorship-resistant networking platform and unified evasion daemon designed for anti-censorship, stealth proxying, and zero-trust mesh routing.

### Core Value Proposition
- **Multi-Protocol Evasion**: Combines userspace TCP segmentation, out-of-band fake packets, TLS Client Hello fragmentation, and SNI desynchronization to defeat Deep Packet Inspection (DPI).
- **Hybrid Multi-Language Runtime**: High-throughput packet transformation and cryptographic primitives in pure Rust (`lumicore`), coordinated by an asynchronous, process-supervising Go daemon, controlled through a modern React 19 / TypeScript UI and native mobile/desktop platforms.
- **Autonomous Self-Healing**: Deterministic health scoring, automatic circuit breaking, exponential backoff, and seamless failover across WireGuard mesh tunnels, MASQUE (HTTP/3) capsules, and distributed relay networks.

---

## 2. Architecture Map & Core Layers

The platform is structured into distinct functional layers with strict trust and ownership boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Tier                        │
│  - Desktop: Wails v3 + WebView2 (src/apps/desktop)          │
│  - Web UI: React 19 + TypeScript (src/packages/control-ui)  │
│  - Android: Kotlin + VpnService (src/apps/android)          │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / WebSocket / JNI
┌──────────────────────────────▼──────────────────────────────┐
│             Control-Plane Daemon (Go 1.26)                  │
│  - REST API & WebSocket Event Hub (internal/adapters/api)    │
│  - Diagnostics, Planning & Admission (internal/analysis)    │
│  - Proxy Engine & Supervision (internal/runtime/proxy)      │
│  - Storage, Crypto & State (internal/infrastructure)        │
└──────────────────────────────┬──────────────────────────────┘
                               │ CGO / lumicore_abi.h
┌──────────────────────────────▼──────────────────────────────┐
│                Native Core (Rust 2021)                      │
│  - High-throughput crypto (ChaCha20-Poly1305, AES-GCM)      │
│  - Network drivers: TUN/TAP, WireGuard IPAM, MASQUE H3      │
│  - Zero-copy buffer management & packet pacing              │
└─────────────────────────────────────────────────────────────┘
```

An interactive visual diagram is available at [`docs/architecture/luminet-architecture.html`](file:///D:/GitHub/LumiNet/docs/architecture/luminet-architecture.html).

---

## 3. Key Directory Map

| Path | Purpose | Primary Language |
| :--- | :--- | :--- |
| [`src/packages/lumicore/`](file:///D:/GitHub/LumiNet/src/packages/lumicore/) | Pure Rust native core; crypto, packet manipulation, and memory-safe C ABI exports. | Rust (Edition 2021) |
| [`src/apps/daemon/`](file:///D:/GitHub/LumiNet/src/apps/daemon/) | Multi-platform Go background daemon, CLI commands, REST/WS APIs, and proxy supervision. | Go (1.26.x) |
| [`src/packages/control-ui/`](file:///D:/GitHub/LumiNet/src/packages/control-ui/) | Shared operator dashboard and control interface, packaged for browser, desktop, and embedded web. | TypeScript, React 19 |
| [`src/apps/desktop/`](file:///D:/GitHub/LumiNet/src/apps/desktop/) | Lightweight Wails v3 desktop application host embedding the control UI bundle. | Go, Wails |
| [`src/apps/android/`](file:///D:/GitHub/LumiNet/src/apps/android/) | Android mobile client integrating Android's `VpnService` via `gomobile` bindings. | Kotlin, Java |
| [`src/packages/contracts/`](file:///D:/GitHub/LumiNet/src/packages/contracts/) | Dependency-neutral contract definitions, discovery descriptors, and version metadata. | Go |
| [`deploy/relays/`](file:///D:/GitHub/LumiNet/deploy/relays/) | Serverless edge relays (Cloudflare Workers, Vercel Edge, AWS Lambda, Google Apps Script). | JavaScript, Node.js |
| [`docs/`](file:///D:/GitHub/LumiNet/docs/) | Architectural specifications, ADRs, runbooks, and developer guides. | Markdown |
| [`scripts/`](file:///D:/GitHub/LumiNet/scripts/) | CI/CD validation suites, build runners, and code generation utilities. | Shell, PowerShell, Python |

---

## 4. Development Workflows & Common Commands

### Prerequisites
- **Go**: 1.26.0+
- **Rust / Cargo**: 1.85.0+ (stable toolchain)
- **Node.js**: 22+ & **npm**: 10+
- **MinGW GCC / LLVM**: Required for CGO compilation when linking `lumicore`

### Common Tasks

#### 1. Building the Entire Workspace
To compile all platform targets (Rust core, Go binaries, and UI assets):
```powershell
# Windows (PowerShell)
.\scripts\build-all.ps1

# Linux / macOS (Bash)
./scripts/build-all.sh
```

#### 2. Running the Control UI
To develop the frontend in browser dev mode:
```bash
cd src/packages/control-ui
npm install
npm run dev
```

To run the frontend test suite (28 comprehensive test suites):
```bash
cd src/packages/control-ui
npm test
```

#### 3. Testing the Go Daemon
For rapid unit testing without CGO linkage:
```powershell
$env:CGO_ENABLED = "0"
cd src/apps/daemon
go test ./internal/...
go vet ./...
```

For full integration tests with Rust staticlib linkage:
```bash
make test-daemon
```

#### 4. Testing the Rust Native Core
```bash
cd src/packages/lumicore
cargo test --locked
```

#### 5. Repository Governance & Consistency Gates
Run the repository validation suite before submitting pull requests:
```bash
make verify-repo
```

---

## 5. Critical Invariants & Conventions

1. **Strict Behavior Preservation**: Refactors and simplifications must never alter runtime protocols, error status mappings, or client side effects.
2. **Read-Only Planner Surfaces**: API endpoints under `/api/system/*-plan` are read-only advisory engines. They characterize network states, compute metrics, and recommend policy without mutating host firewall rules, dialing remote endpoints, or starting processes.
3. **Fail-Closed Security Invariant**: If a cryptographic assertion, tunnel state verification, or required security guard (DNS, QUIC, STUN, DoH, IPv6) fails, the system must fail closed—never defaulting to an insecure open state.
4. **No Placeholders**: Never check in `TODO`, placeholder implementations, or truncated ellipses in functional code or documentation.
5. **Porting & Structural Naming**: Do not inherit external or vendor names in filenames or types; use standardized domain terminology (e.g., `ecc_curve.rs` instead of third-party package names).

---

## 6. Your First Pull Request

1. **Branch off `main`**: Create a focused topic branch.
2. **Implement surgical edits**: Keep diffs minimal and confined to required layers.
3. **Run local validations**:
   - `src/packages/control-ui`: `npm test`
   - `src/apps/daemon`: `go vet ./...` and `go test ./...`
   - `src/packages/lumicore`: `cargo test`
4. **Verify cleanliness**: Ensure `git status -u` reports zero untracked artifacts or scratch files.
