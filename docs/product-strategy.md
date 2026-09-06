# 🎯 LumiNet Productization & Competitive Strategy

> **Status:** Product direction and future productization strategy. Maturity labels and workflow aspirations do not override current capability truth in [`current-system.md`](current-system.md), live code/tests, or release verification.

This document details the product design, competitive benchmarking, and future productization strategies for the LumiNet platform.

---

## 1. Five-Workflow Product Model

LumiNet organizes user interactions around five workflows rather than focusing on low-level command parameters or internal codebase structures:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        LumiNet Console Cockpit                         │
├──────────────┬──────────────┬──────────────┬──────────────┬────────────┤
│   Workflow 1 │   Workflow 2 │   Workflow 3 │   Workflow 4 │ Workflow 5 │
│   Diagnose   │   Scan       │   Evaluate   │   Control    │ Operate    │
│   Network    │   Targets    │   Proxies    │   System     │ LumiNet    │
└──────────────┴──────────────┴──────────────┴──────────────┴────────────┘
```

### 1.1 Diagnose Network (Workflow 1)
* **Goal:** Audit local connection health, detect hijacking, and generate diagnostic reports.
* **Sub-workflows:** Basic ping connectivity → DNS resolver verification → HTTPS/TLS validity verification → captive portal checks → SNI blocking detection → speed sweeps → PDF/HTML report export.
* **Status Details:** Rather than reporting raw success or failure, the diagnostic pipeline scores path health using confidence metrics and explicit reason codes.

### 1.2 Scan Targets (Workflow 2)
* **Goal:** Coordinate active target sweeps and targeted port discovery campaigns.
* **Sub-workflows:** Setup target CIDR/IP pools → profile selector (ICMP/TCP/DNS/TLS/SNI) → resource budget preview → sweep launch → live streaming evidence timeline → checkpoint resume.
* **Data Streams:** Results are saved incrementally to the SQLite database during execution and broadcast to active subscribers via WebSocket events.

### 1.3 Evaluate Proxies (Workflow 3)
* **Goal:** Import, parse, test, score, and rank outbound proxy nodes.
* **Sub-workflows:** Import proxy URI lists → parse configurations to AST schemas → validate using conformance checks → batch test latencies through a single shared engine process → calculate performance score → export ranked configs.
* **Batch Optimization:** Testing uses a single shared batch engine configuration, avoiding the overhead of launching separate processes for each tested proxy node.

### 1.4 Control System State (Workflow 4)
* **Goal:** Modify and inspect host OS network configurations.
* **Sub-workflows:** Read active interface configurations → preview proposed transitions → apply configuration modifications via transactional managers → run connectivity checks → commit or rollback.
* **Safety Boundaries:** Mutations (such as DNS adjustments or proxy redirection) are backed up before change application. In the event of a daemon crash, the watchdog handles the restoration of default host settings.

### 1.5 Operate LumiNet (Workflow 5)
* **Goal:** Monitor system performance, audit jobs histories, and manage capabilities.
* **Sub-workflows:** View job queue queues and statuses → monitor event log logs (with sequence replay) → inspect Prometheus-compatible `/metrics` → manage capability registries → run `doctor` validations.

---

## 2. Competitive Benchmarking

LumiNet compares favorably to existing diagnostic and proxy-testing tool suites, serving as a unified control plane rather than a collection of scripts.

| Competitor | Core Capabilities | LumiNet Advantage |
|---|---|---|
| **Nmap** | Target port scanning, OS fingerprinting, scripting engine (NSE) | Streaming result persistence, WebAssembly sandbox, and active circumvention evasion |
| **sing-box / Xray** | Low-level tunneling client, proxy protocol parsing, routing rules | Simplified visual cockpit, automated diagnostic runbooks, and transactional system configuration rollback |
| **Nekoray / v2rayN** | Client UI wrapper for proxy cores | Bounded concurrency scheduler, headless-first design, structured local IPC, and plugin extensions |
| **Wireshark** | Deep packet analysis and inspection | Active bypass injection (`paqet`), automated routing configurations, and zero-trust local control plane |

---

## 3. Subsystem Maturity Classification

LumiNet assigns maturity labels to its features to guide development and deployment stability:

| Subsystem | Components | Maturity Label | Deployment Guidance |
|---|---|---|---|
| **LumiScan** | ICMP, TCP, DNS target sweeps, evidence exporter | **Stable** | Bundled in all release distributions |
| **LumiDiag** | 8-phase diagnostic runbooks, PDF report writer | **Stable** | Bundled in all release distributions |
| **LumiSystem** | Win32 DNS Helper, transaction manager | **Beta** | Requires administrator permissions |
| **LumiProxy** | AST parser, shared batch tester | **Beta** | Standard profile execution |
| **LumiGuard** | DNS poisoning detector, CA trust manager, watchdog | **Beta** | Watchdog runs as a detached process |
| **Plugin Sandbox** | wazero WebAssembly executor | **Experimental** | Disabled by default in standard configurations |
| **Covert Transport** | GDocs Zephyr relay, GAS CDN client | **Experimental** | Isolated to remote build profiles |
| **Mobile Bridge** | Standard Android VPN Service, JNI socket protection | **Experimental** | Standard profile (Play Store compliant) vs. Rooted Zygisk (Stealth profile) |
