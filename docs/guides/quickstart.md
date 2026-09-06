# 🚀 LumiNet Quick Start & Administration Guide

Welcome to the **LumiNet** setup and operations manual. This guide will walk you through the system prerequisites, binary deployment, compilation from source, command-line operations, evasion tunnel setup, and recovery runbooks.

---

## 1. Installation & Deployment

LumiNet can be run by downloading pre-compiled binaries or by compiling the codebase from source.

### 1.1 Downloading Pre-compiled Releases
Pre-compiled packages for Windows (x64), Linux (x86_64), and macOS (Apple Silicon/Intel) are available on the [LumiNet Releases page](https://github.com/maybeknott/luminet/releases).
1. Download the archive matching your operating system.
2. Extract the archive into a permanent directory of your choice.
3. Add the extraction path to your system's `PATH` variable to enable global terminal access.

---

## 2. Compiling from Source

Host daemon builds link the Rust core through CGO and require a compatible C compiler toolchain. Android uses the generated pure-Go mobilebind AAR path and does not require the host Rust-CGO bridge.

### 2.1 Toolchain Prerequisites

| Language/Tool | Version | Purpose | Installation |
|:---|:---|:---|:---|
| **Rust** | See `src/packages/lumicore/Cargo.toml` | Compiles the native core | [rustup.rs](https://rustup.rs) |
| **Go** | 1.26.5 | Compiles the daemon and API | [go.dev/dl](https://go.dev/dl/) |
| **C Compiler** | GCC 12+ | Links Rust's static library via CGO | See Platform Guides below |
| **Node.js** | 22.16.0 | Builds the shared control UI | [nodejs.org](https://nodejs.org) |
| **npm** | Bundled with Node | Installs/builds `src/packages/control-ui` | [nodejs.org](https://nodejs.org) |

### 2.2 Installing the C Compiler Toolchain

#### Windows (MSYS2 MinGW-w64)
1. Download and run the installer from [msys2.org](https://www.msys2.org/).
2. Open the **MSYS2 UCRT64 Terminal** and execute:
   ```bash
   pacman -S mingw-w64-ucrt-x86_64-gcc git make
   ```
3. Add the MinGW binary path (`C:\msys64\ucrt64\bin`) to your Windows environment `Path`.
4. Open a new PowerShell terminal and verify: `gcc --version`.

#### Linux (Ubuntu/Debian)
Install developer build tools and library headers via `apt`:
```bash
sudo apt update
sudo apt install build-essential gcc git make -y
```

#### macOS (Xcode Command Line Tools)
Install Apple developer tools:
```bash
xcode-select --install
```

### 2.3 Compilation Workflow

#### Windows Deployment (PowerShell)
```powershell
# Clone the repository
git clone https://github.com/maybeknott/luminet.git
cd LumiNet

# Execute the Windows build script
.\scripts\build-all.ps1

# Run the compiled binary from the build directory
.\build\luminet.exe serve
```

#### Linux & macOS Deployment (Terminal)
```bash
# Clone the repository
git clone https://github.com/maybeknott/luminet.git
cd LumiNet

# Grant execution rights to the Unix build script
chmod +x scripts/build-all.sh
./scripts/build-all.sh

# Run the compiled binary
./build/luminet serve
```

---

## 3. Starting the Daemon (`serve` command)

LumiNet functions as a background orchestrator daemon that coordinates scanning runs and proxy tunnels.

```bash
# Start the daemon on the default port (8470)
luminet serve

# Start the daemon on a custom port and restrict to localhost
luminet serve --port 9090 --host 127.0.0.1

```

### 3.1 Initial Operations Checklist
When `luminet serve` is executed, the daemon performs these ownership-critical startup steps:
1. **Host-network recovery:** Restores any interrupted durable DNS/routing mutation before accepting new work.
2. **Watchdog ownership:** Launches the independent host-network watchdog used for crash recovery.
3. **Database/runtime initialization:** Opens and migrates the local SQLite store, then initializes the daemon job/runtime owners.

Host-network snapshots are captured when a DNS or routing mutation is applied; startup does not fabricate a new backup merely by inspecting adapters.

---

## 4. CLI Subcommand Reference & Examples

The Cobra command definitions under `src/apps/daemon/cmd/` are authoritative. Use `luminet <command> --help` for the current flag surface.

### 4.1 Subnet & Service Port Scanning (`scan`)

#### Stateless ICMP Sweep
Ping all hosts in a target CIDR range concurrently:
```bash
# Run a sweep with 200 concurrent threads and a 1500ms timeout
luminet scan icmp 192.168.1.0/24 --concurrency 200 --timeout 1500
```

#### TCP Port Scan
Audit TCP ports and report connection results:
```bash
# Scan common ports on a host and output results in JSON format
luminet scan ports 10.0.0.15 --ports 21,22,80,443,3306,8080 --output json
```

#### TLS Certificate Inspection
Inspect the TLS configuration of a target endpoint:
```bash
luminet scan tls example.com --port 443
```

#### SNI Block Checker
Probe whether a local firewall filters a specific Server Name Indication (SNI) header:
```bash
luminet scan sni blockeddomain.com
```

---

### 4.2 Comprehensive Network Diagnostics (`diagnose`)

The diagnostics tool runs the current diagnostic pipeline. The active phase count and available flags are defined by `src/apps/daemon/cmd/diagnose.go`; older six-phase descriptions are historical.

```bash
# Run a full diagnostic check
luminet diagnose

# Run specific phases (e.g., DNS Integrity and Portal Checks) and export the report
luminet diagnose --phases 2,4 --json --output diagnostics-report.json
```

---

### 4.3 Proxy Operations & Subscriptions (`proxy`)

#### Benchmarking Proxy Latency
Bulk test a list of proxies from a text file:
```bash
# Test proxies using 32 parallel threads and measure download latency
luminet proxy test -f my_proxies.txt --concurrency 32 --speed-test
```

#### Managing Subscription Links
Fetch and parse a subscription URL:
```bash
luminet proxy subscribe https://example-provider.com/sub/raw?token=123
```

#### Exporting Verified Working Proxies
Filter working proxies and export them to a Clash-compatible format:
```bash
luminet proxy export -f my_proxies.txt --format clash --output clash-config.yaml
```

---

### 4.4 System Configuration & Evasion Setup (`system`)

#### Modifying System DNS Servers
Set system-wide DNS to secure public servers (e.g., Quad9):
```bash
luminet system dns apply 9.9.9.9 149.112.112.112
```

#### Resetting Adapter DNS Configuration
Return the active adapter to its platform-default/DHCP DNS configuration:
```bash
luminet system dns clear
```

#### SOCKS5 Active Evasion Tunnel
Start a local SOCKS5 tunnel with TCP segment splitting and auto-SNI desynchronization:
```bash
# Enable SOCKS5 evasion on port 1080 with SNI splitting enabled
luminet system evasion-tunnel start --port 1080 --split 3 --delay 10 --auto-sni
```

#### System Proxy Routing
Point the host proxy settings at the local tunnel when that routing mode is desired:
```bash
luminet system proxy-settings apply 127.0.0.1:1080

# Return to direct host routing
luminet system proxy-settings clear
```

---

## 5. Recovery Runbook

### 5.1 Restoring DNS Settings After an Unexpected Crash
The daemon and watchdog own durable host-network recovery. If you need to manually return the active adapter to platform-default/DHCP DNS configuration, run:

```powershell
luminet system dns clear
```

If the CLI fails to execute due to file lockouts, reset the network adapter settings using native OS shell tools:

#### Windows (Administrator PowerShell)
```powershell
# Reset all Ethernet and Wi-Fi adapters to receive DNS dynamically via DHCP
Get-NetIPInterface | Where-Object { $_.ConnectionState -eq 'Connected' } | Set-DnsClientServerAddress -ResetServerAddresses
```

#### Linux (Terminal)
```bash
# Restore default resolv.conf via Systemd resolver
sudo systemctl restart systemd-resolved
```
