# ⚙️ LumiNet Core Subsystems and Operational Pillars

> **Historical functional specification.** This document preserves an earlier product taxonomy and capability vision. It is not capability truth. Current availability is owned by live routes/runtime guards and `../current-system.md`.


LumiNet organizes its features and services into five functional subsystems, which govern all REST endpoints, system wrappers, and background automation runners.

---

## 1. 🔍 LumiScan — Stateless Scanning Subsystem

LumiScan coordinates high-precision, stateless network audits by shuffing targets using the Blackrock block cipher (porting masscan/zmap shuffler principles) to randomize address traversal paths, preventing firewall triggering from sequential scans.

### 1.1 ICMP Subnet Sweep
* **Implementation**: Uses async raw ICMP sockets inside Rust (`src/packages/lumicore/src/icmp/`).
* **Features**: Configurable rate ceilings (PPS), socket buffers, and precision round-trip time (RTT) measurements.

### 1.2 Parallel TCP Port Sweep
* **Implementation**: Uses Tokio's async TCP stream dials (`src/packages/lumicore/src/tcp/`).
* **Features**: Simultaneous multi-port sweeps, response latency tracking, and banner-grabbing filters to read application signatures.

### 1.3 DNS Harvest & TLS Certificate Auditing
* **DNS Probes**: Queries target hostnames across major record types (`A`, `AAAA`, `MX`, `CNAME`, `TXT`, `NS`) concurrently.
* **TLS Audits**: Conducts secure TLS handshakes to extract version details, active cipher suites, and validation chain parameters.

---

## 2. 🛡️ LumiGuard — Security & Active Warnings Subsystem

LumiGuard acts as a zero-trust network health and configuration integrity watchdog.

### 2.1 DNS Hijacking & SSL Interception Audits
* **DNS Checks**: Runs parallel resolutions over UDP and secure DoH consensus endpoints side-by-side. If the IP configurations mismatch, the engine flags a DNS hijacking alert.
* **SSL MITM Checks**: Inspects SSL certificates. If a firewall proxy root (such as Zscaler, Fortinet, or Sophos) is injected, it triggers a warning interface.

### 2.2 NCSI Windows Registry Watchdog
* **Active Probe Host Override**: Modifies Windows NCSI parameters (such as `ActiveWebProbeHost`) to bypass validation blockages caused by local ISP filters.
* **Standby Watchdog**: Launches a detached watchdog process (`watchdog.exe`) on system boot to clean up routing tables and restore network states if the main daemon exits ungracefully.

---

## 3. 🌐 LumiProxy — Subscription & Parse Subsystem

LumiProxy processes configurations and scrapes proxy nodes from multiple subscription formats.

### 3.1 Multi-Protocol Parser
* **Formates**: Parses VMess, VLESS, Shadowsocks, Trojan, Hysteria2, TUIC, and WireGuard config lines.
* **Scraper Integration**: Aggregates proxy nodes from external HTTP endpoints, channels, and public Telegram MTProto lists.

### 3.2 Edge Worker Routing
* **Serverless Dialers**: Directs traffic through serverless edge worker scripts (e.g. Cloudflare Workers) via customized VLESS/Trojan WebSocket wrappers, using them as proxy relay hops.

---

## 4. 🩺 LumiDiag — Six-Phase Runbook Diagnostics Subsystem

LumiDiag provides detailed automated diagnostics runbooks to troubleshoot local connectivity:

* **Six-Phase Sequence**:
  1. *Connectivity*: Pings gateway IP and local loopbacks.
  2. *DNS Integrity*: Verifies secure DNS resolution.
  3. *TLS Validity*: Audits secure HTTPS handshakes.
  4. *Portal Check*: Scans for redirecting captive portals.
  5. *Evasion Scanner*: Tests segment-splitting capabilities.
  6. *Speed Grade*: Measures download bandwidth.
* **Export Templates**: Formats diagnostic parameters into HTML or PDF reports.

---

## 5. ⚙️ LumiSystem — OS Configuration Integrators

LumiSystem links user configurations to native OS network parameters:

* **DNS Switcher**: Automates applying DNS configurations on network adapters. Default configurations are cached in SQLite for automatic restoration.
* **Dynamic DNS (DDNS)**: Schedules cron jobs that update dynamic DNS endpoints for Cloudflare, No-IP, No-IP, and Dynu over SSL connections.
* **System Proxy Settings**: Automates setting up system-wide SOCKS5 proxy settings to redirect HTTP/HTTPS traffic through the SOCKS5 evasion tunnel.
