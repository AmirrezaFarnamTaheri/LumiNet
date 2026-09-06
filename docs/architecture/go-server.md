# 🌐 Go Server Architecture & Operations Manual

This document provides a comprehensive technical overview of the orchestration layer located under `src/apps/daemon/`. It details package design, API schemas, background job workers, anti-censorship proxy layers, and system integration interfaces.

---

## 1. Directory & Package Mapping

The Go orchestrator codebase is organized into several directories to isolate API boundaries, database persistence, and native GUI rendering modules:

```
src/apps/daemon/
├── cmd/                         # executable composition and Cobra adapters
└── internal/
    ├── foundation/              # config, crypto, evidence, stores, secrets, traffic stats
    ├── native/bridge/           # Go ↔ LumiCore C ABI seam
    ├── protocols/               # protocol/framing/reliability implementations
    ├── platform/                # host-network, process, and mobile platform adapters
    ├── networking/              # DNS, routing, geo, canonical proxy configuration
    ├── analysis/                # diagnostics, scanner, provider classification
    ├── integrations/            # subscriptions, relays, provisioning, presets, notifications
    ├── runtime/
    │   ├── decoy/               # daemon-owned background decoy traffic lifecycle
    │   ├── mobilecore/          # mobile TUN/runtime lifecycle owner
    │   ├── proxy/               # evasion + ephemeral proxy qualification runtime
    │   ├── routingplugin/       # routing-provider policy owner
    │   ├── runtimecore/         # long-lived Tor/Psiphon runtime-engine owner
    │   ├── safety/              # shared safety-policy truth
    │   ├── trust/               # peer trust/reputation owner
    │   └── warp/                # WARP/WireGuard scan/configuration owner
    ├── workflows/
    │   ├── jobs/                # typed secret-safe async jobs
    │   └── scheduler/           # scheduled orchestration
    └── adapters/
        ├── api/                 # Gin/WebSocket transport adapter
        └── mobilebind/          # gomobile translation adapter
```

---

### 1.1 Runtime engine ownership

Long-lived runtime engines cross one seam at `internal/runtime/runtimecore`. Its interface is `Start`, `Stop`, `Status`, and `Close`; Tor and Psiphon are the two production adapters behind that seam. The proxy `CoreManager` is intentionally separate because it launches temporary Xray/sing-box processes for proxy testing rather than owning daemon runtime state. The `/api/system/tailscale` compatibility route reports embedded Tailscale as unsupported and never starts the experimental mock adapter.

## 2. API Server & Middleware Chain

The daemon runs an HTTP REST and WebSocket server using the Gin framework. It is configured to run on localhost by default to ensure local isolation.

Request-scoped handlers propagate `c.Request.Context()` into storage, diagnostics, and network work. Background lifetime is never created by HTTP handlers; daemon-owned work is wired at server construction/shutdown.

### 2.1 Complete Middleware Chain
Every HTTP request goes through this middleware pipeline:

```
  HTTP Client Request 
          │
          ▼
   [ Gin Recovery ]  <── Captures runtime panics and returns 500
          │
          ▼
   [ Gin Logger ]    <── Standard output request audit logger
          │
          ▼
   [ CORS Handler ]  <── Configured for localhost interface checks
          │
          ▼
   [ Auth Token ]    <── Verifies X-API-Key headers
          │
          ▼
   [ WebSockets ]    <── Upgrades connections (e.g. for /ws)
          │
          ▼
   Target API Controller
```

### 2.2 WebSocket telemetry ownership

`internal/adapters/api.Hub` is the single live WebSocket transport module. It derives RX/TX byte rates from the canonical cumulative counters in `internal/foundation/trafficstats` and emits one `METRICS_UPDATE` JSON envelope per WebSocket frame. The first counter sample establishes a baseline; counter resets establish a new baseline instead of producing an underflow spike. Tunnel latency is `null` until a real latency measurement owner exists; zero is reserved for a measured zero. Diagnostic jobs remain authoritative through their existing job/REST status interfaces rather than a separate `DIAGNOSTIC_LOG` telemetry contract. The retired standalone telemetry WebSocket server is preserved under `labs/daemon/system-alternates/`.

*   **WebSocket Origin Validation:** The WebSocket upgrade path enforces strict origin checks to prevent Cross-Site WebSocket Hijacking (CSWSH) attacks:
    ```go
    var upgrader = websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool {
            origin := r.Header.Get("Origin")
            return origin == "" || strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1")
        },
    }
    ```

---

## 3. Endpoints & Schema Specification

The tables below define the schemas and formats used by the REST API:

### 3.1 Subnet ICMP Sweep (`POST /api/scans`)
*   **Request Schema:**
    ```json
    {
      "target_cidr": "192.168.1.0/24",
      "concurrency": 128,
      "timeout_ms": 1000
    }
    ```
*   **Response Schema (202 Accepted):**
    ```json
    {
      "job_id": "job_d98124b8-f076-4d1a-8263-448f",
      "status": "queued",
      "created_at": "2026-06-22T01:00:00Z"
    }
    ```

### 3.2 SOCKS5 Evasion Tunnel (`POST /api/system/evasion-tunnel`)
*   **Request Schema:**
    ```json
    {
      "action": "start",
      "socks_port": 1080,
      "split_offset": 3,
      "split_delay_ms": 10,
      "auto_sni": true,
      "fragment_min": 100,
      "fragment_max": 500,
      "fragment_delay": 15,
      "filter_scope": "tlshello",
      "dns_resolver": "9.9.9.9"
    }
    ```
*   **Response Schema (200 OK):**
    ```json
    {
      "status": "active",
      "port": 1080,
      "pid": 1392
    }
    ```

### 3.3 Served Route Inventory (`GET /api/routes`)

`GET /api/routes` is the runtime authority for route existence. Each served route includes method/path plus workflow, capability, availability, and deprecation metadata where applicable. Removed covert-tracker, extension, and synthetic shortlink handlers are not served and are not product capability.

---

## 4. Background Job Scheduling Subsystem

The Job Scheduler (`internal/workflows/jobs/`) manages and executes concurrent diagnostic and scanning tasks.

```
       [ Client POST Request ]
                  │
                  ▼
         [ Model Validation ]
                  │
                  ▼
         [ Persist to SQLite ] 
                  │
                  ▼
      [ Add to Schedule Queue ]
                  │
                  ▼
      [ Spawn Go Async Runner ] ──► [ CGO / Rust Tokio Thread ]
                  │
                  ├─► Read FFI results
                  ├─► Save results to DB
                  └─► Dispatch WS status frame
```

*   **Concurrency Rules:** The Job Scheduler limits concurrent scanning runs using a bounded worker pool. The Go orchestrator dynamically spins up runners based on the global concurrency configuration, while Rust's static library uses semaphores to prevent system socket exhaustion.
*   **Memory Safety (Cloning structs):** The job struct contains synchronization mutexes. Direct struct copying duplicates the mutex memory state, which can lead to deadlocks or panic states. The system enforces explicit data cloning:
    ```go
    func (j *Job) SafeClone() *Job {
        j.mu.RLock()
        defer j.mu.RUnlock()
        return &Job{
            ID:        j.ID,
            Type:      j.Type,
            Status:    j.Status,
            Progress:  j.Progress,
            CreatedAt: j.CreatedAt,
            UpdatedAt: j.UpdatedAt,
            Config:    j.Config,
            Result:    j.Result,
            Error:     j.Error,
        }
    }
    ```

---

## 5. SOCKS5 Evasion Tunnel State Machine

The SOCKS5 Evasion Tunnel (`internal/runtime/proxy/evasion_tunnel.go`) captures outbound traffic and applies packet-level manipulation:

```
  [ SOCKS5 Server ] ──► [ Receive Connect CMD ] ──► [ Read IP & Port ]
                                                             │
                                                             ▼
                                                   [ Dial Remote Server ]
                                                             │
                                     ┌───────────────────────┴───────────────────────┐
                                     ▼                                               ▼
                              [ Plaintext HTTP ]                                [ TLS Stream ]
                                     │                                               │
                                     ▼                                               ▼
                             [ Case Mutations ]                              [ Parse ClientHello ]
                        Mutate header casing patterns                                │
                                                                                     ▼
                                                                             [ TLS SNI Finder ]
                                                                             Extract extension
                                                                                     │
                                                                                     ▼
                                                                             [ TCP split writes ]
                                                                             Slices SNI string
```

1. **Connection Capture:** The SOCKS5 listener negotiates handshakes, validates requested commands (`0x01` for Connect), and checks target destinations.
2. **Dynamic Evasion Routing:**
   * **TCP Segment Splitting:** Slices the outgoing payload array at a specified split offset. It writes the first segment to the socket, yields for a configurable delay, and then writes the remaining payload.
   * **Smart SNI split:** Checks the initial payload for a TLS ClientHello identifier (`0x16 0x03`). If found, it parses the payload structure to extract the Server Name Indication (SNI) extension. The engine then splits the payload array at the SNI boundary and writes the fragments with a timing delay.
   * **Plaintext Case Mutations:** If HTTP GET/POST headers are detected, the engine modifies the header capitalization (e.g. `Host: -> hOsT:`) to cause deep packet parsing failures in legacy firewalls.

---

## 6. System Registry & Commands Interface

System configuration operations interface directly with operating system APIs and commands:

### 6.1 Windows Platform
*   **System DNS Management:** Updates adapter configurations using `netsh` commands:
    ```bash
    netsh interface ipv4 set dns name="Ethernet" source=static address=9.9.9.9
    ```
*   **System HTTP/SOCKS Proxy Registry Keys:** Modifies keys under `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`:
    *   `ProxyEnable` (DWORD): `1` to enable, `0` to disable.
    *   `ProxyServer` (SZ): `http://127.0.0.1:1080` (proxy endpoint).
    *   `ProxyOverride` (SZ): bypass configurations.
*   **Auto-Start Registry Settings:** Modifies key mappings under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

### 6.2 Linux Platform
*   **System DNS Integration:** Interfaces with Systemd Name Service resolvers:
    ```bash
    resolvectl dns eth0 1.1.1.1 8.8.8.8
    ```

### 6.3 macOS Platform
*   **DNS & Proxy Settings:** Interfaces with system network configuration commands:
    ```bash
    networksetup -setdnsservers "Wi-Fi" 9.9.9.9 149.112.112.112
    ```

---

## 7. External Plugin System Design

The server supports external binary discovery and communication via standard streams:

```
  Go Server Engine ──► [ JSON-RPC 2.0 Payload ] ──► [ Write to Plugin stdin ]
                                                             │
                                                             ▼
                                                      [ Plugin Process ]
                                                             │
                                                             ▼
  Go Server Engine ◄── [ JSON-RPC 2.0 Response ] ◄── [ Read from stdout ]
```

*   **Plugin Discovery:** The server scans the `plugins/` directory for `plugin.json` manifests.
*   **JSON-RPC 2.0 Interface:** The server executes the plugin binary, writes JSON-RPC payloads to `stdin`, and reads responses from `stdout`.
*   **Events Pipeline:** Standard events (such as `scan_result`, `proxy_result`, and `diag_complete`) are piped to the plugins to execute custom hooks.
