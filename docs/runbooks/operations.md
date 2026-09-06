# 📋 LumiNet Operational Playbook & Reference Manual

This document details the operational guidelines, project remediation roadmap history, assumptions, system constraints, and the external reference index for the LumiNet platform.

---

## 1. Project Remediation Timeline (Roadmap Archive)

All critical architectural, engineering, and security gaps have been resolved across four development phases:

### Phase 0 — Repository Purification & Build Integrity
* **Supply Chain Sanitization:** Native WinDivert binaries are not tracked or bundled. The retired repository fetch helper was removed because its placeholder integrity data could not establish a trusted supply chain; operators enabling Windows raw packet modes must supply a trusted WinDivert distribution explicitly.
* **Misplaced Workspaces:** Deleted the unreferenced and duplicate nested Cargo workspace (`scratch_tuic`) from the Go server directory structure.
* **Credentials Sanitization:** Removed developer-specific keys (`node_creds.json`) and added corresponding ignore rules for local state caches.
* **Safe Defaults:** Set default background health audits and domain host overrides to `disabled` inside configuration defaults to prevent unexpected host outbound calls.

### Phase 1 — Immediate Stabilization & API Security
* **Capability Registry Integration:** Created route-level middleware gates to restrict access to API endpoints based on workflow capabilities and maturity level.
* **IPC Gating:** Implemented API key handshake verification for local loopback TCP routes and Unix Domain Socket (UDS) access.
* **CGO-Free DB Driver:** Switched the SQLite driver from the CGO-dependent `go-sqlite3` implementation to the pure-Go `modernc.org/sqlite` package.

### Phase 2 — Architectural Decomposition & Mutational Integrity
* **Decomposed Monoliths:** Decomposed the `EvasionTunnelManager` into decoupled interfaces (`EvasionConfigContext`, `TunnelListener`, `DnsForwarder`).
* **Transactional State Change:** Wrapped OS network configuration mutations inside transactional blocks with snapshot backup and watchdog monitors.
* **Watchdog Integration:** Configured the `watchdog/main.go` tool to launch during server daemon startup and monitor the process.

### Phase 3 — High-Performance FFI Data Plane
* **Binary FFI Protocol:** Configured FFI boundaries to use binary-packed C structs instead of serializing payloads to JSON.
* **Evidence Streaming:** Updated active scanner and diagnostics subsystems to persist results incrementally to SQLite and broadcast progress over WebSocket channels.
* **Radix Domain Routing:** Moved domain rule filters into the Rust core, utilizing radix trie search algorithms.

---

## 2. System Assumptions & Operational Constraints

LumiNet operations rely on several assumptions regarding host system privileges and hardware parameters:

### 2.1 Host Privileges and Security Policies
* **Administrator/Root access:** To modify system DNS, register WFP rules, or bind raw packet sockets, the daemon process must be run with Administrator privileges on Windows, or `CAP_NET_RAW` / `CAP_NET_ADMIN` capabilities on Linux.
* **Windows Driver Signing Policy:** Using `WinDivert` requires loading kernel-mode drivers. On Windows systems with strict Driver Signature Enforcement (DSE), drivers must be signed by Microsoft or an authorized certificate authority.

### 2.2 Memory and Process Isolation
* **Cross-Language FFI:** Rust FFI callbacks interact with the Go scheduler via standard pointers. Memory allocations must be released back to the allocating runtime to avoid heap corruption or memory leaks.
* **CGO Overhead:** Frequent transition crossings between Go and Rust cause context switching delays. Hot packet processing loops must run entirely inside Rust, using ring-buffer channels to stream results to Go.

---

## 3. External Reference Index

The table below catalogs official references, standards, and specifications utilized during the architecture design of the LumiNet platform.

| Reference | Scope / Purpose | Relevance in LumiNet |
|---|---|---|
| **Nmap Output Format** | Diagnostic output standard | Maps to `ProbeEvidence` schemas, XML/JSON exports, and reason-code mappings |
| **Masscan Project** | Stateless scanning design | Random target permutation generator and rate-limiting bucket structures |
| **OpenTelemetry Go** | System observability | Structured trace context, trace propagation over CGO, and standard event log formatting |
| **Prometheus Specification** | Daemon performance metrics | Standard format rules for exposing `/metrics` performance records |
| **sing-box Configuration** | Configuration validation | Employs `sing-box check` API tests to pre-validate proxy profiles before execution |
| **SQLite WAL Specifications** | Database storage safety | Informs Write-Ahead Logging (WAL) and concurrent thread configurations |
| **Model Context Protocol** | AI integration standard | Standardizes stdio-based control, tool registration, and agent automation schemas |
| **io_uring Networking** | High-performance I/O | Standard design rule for high-speed Linux zero-copy packet interfaces |
| **gVisor netstack** | Memory-safe TCP/IP stack | Replaces C-based lwIP in Android standard VPN profiles |
| **Wails v3 Framework** | Desktop application shell | Cross-platform Go-first desktop GUI wrapper |
