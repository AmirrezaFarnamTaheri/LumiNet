# 🛠️ LumiNet Developer & Technical Manual

This manual provides detailed instructions on the software architecture, memory boundaries, database schemas, internal bypass mechanics, and compilation processes of the **LumiNet** platform.

---

## 1. Multi-Language FFI Communication Boundary

Host daemon builds link `src/packages/lumicore` through CGO. Rust source is the implementation/layout authority; Go declares exactly the Rust exports it actually calls in `src/apps/daemon/internal/native/bridge/lumicore_abi.h`. The ABI checker rejects parallel declarations and compares the shared structs against Rust `#[repr(C)]` / `#[repr(C, packed)]` definitions.

The active bridge has two compatibility styles:

- the versioned generic binary/envelope call `lumicore_call`, streaming, and ABI version negotiation;
- retained legacy JSON/string exports still called by `core.go`, with Rust-owned strings released through `free_string`.

`lumicore_abi.h` declares only the Rust symbols and layouts the Go host actively consumes, so Go source files do not maintain independent Rust prototypes. Rust-internal packed scan payload types stay in Rust and are not exposed through the private C header. The former specialized binary scan mock is preserved under `labs/` rather than advertised as a live host capability.

### 1.1 Link authority

Do not add `#cgo LDFLAGS` with hard-coded LumiCore paths or platform libraries. `scripts/checks/lumicore_link.py` builds/locates the Cargo static archive for the selected profile/target and consumes Cargo's `native-static-libs` output. Make, local scripts, CI, and release use that resolver.

### 1.2 Ownership rules

- Go-owned buffers passed into synchronous binary calls remain Go-owned for the duration of the call.
- Rust-owned legacy string results are copied into Go and released with the Rust `free_string` export.
- Streaming callbacks keep callback/user-data memory valid through the terminal callback; cancellation only signals Rust and does not free host callback state.
- Every transferred TUN descriptor in the mobile path becomes Go-owned immediately after `detachFd()`; startup rejection/failure still closes it.
- Panics must not unwind across the C ABI.

---

## 2. SQLite Database Schema Layout

The Go daemon stores active configuration, job, DNS, and operations state in a local SQLite database named `luminet.db`. Historical migrations still create the retired `covert_links` / `covert_visits` tables so existing databases upgrade deterministically; no current route or command writes them.

```
                  ┌───────────────────────────────┐
                  │          covert_links         │
                  ├───────────────────────────────┤
                  │ id (INTEGER Primary Key)      │
                  │ name (TEXT, Unique)           │
                  │ redirect_url (TEXT)           │
                  │ created_at (DATETIME)         │
                  └───────────────┬───────────────┘
                                  │ (1-to-many relationship)
                                  ▼
                  ┌───────────────────────────────┐
                  │         covert_visits         │
                  ├───────────────────────────────┤
                  │ id (INTEGER Primary Key)      │
                  │ link_id (INTEGER FK)          │
                  │ client_ip (TEXT)              │
                  │ user_agent (TEXT)             │
                  │ os_family (TEXT)              │
                  │ device_brand (TEXT)           │
                  │ country_code (TEXT)           │
                  │ visited_at (DATETIME)         │
                  └───────────────────────────────┘
```

### 2.1 Historical Covert-Tracker Migration Schema (Retired Capability)
```sql
CREATE TABLE IF NOT EXISTS covert_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    redirect_url TEXT NOT NULL,
    created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS covert_visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id INTEGER NOT NULL,
    client_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    os_family TEXT NOT NULL,
    device_brand TEXT NOT NULL,
    country_code TEXT NOT NULL,
    visited_at DATETIME NOT NULL,
    FOREIGN KEY(link_id) REFERENCES covert_links(id) ON DELETE CASCADE
);
```

### 2.2 System & Operations Management Schemas
```sql
CREATE TABLE IF NOT EXISTS system_dns_backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    adapter_name TEXT NOT NULL,
    dns_addresses TEXT NOT NULL,
    backup_time DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL,
    schedule_cron TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    last_run DATETIME
);
```

---

## 3. Internal Mechanics of Evasion & Bypass Tunnels

### 3.1 SOCKS5 Smart Evasion Desynchronization
The SOCKS5 local tunnel intercepts plaintext HTTP and encrypted HTTPS streams to perform TCP packet division:

1. **Auto-Split TLS SNI:** The engine scans the initial bytes of incoming TCP streams for a TLS ClientHello pattern (`0x16 0x03`). If detected, it parses the handshake layout:
   * Identifies the Record Layer length.
   * Traverses TLS extensions to find the Server Name Indication (SNI) extension.
   * Splits the ClientHello TCP packet at the exact boundary of the SNI hostname string.
   * Sends the first segment, pauses for a configurable delay (e.g., 5-10ms), and then transmits the remaining payload. This confuses stateful signature matches on intermediate DPI firewalls.
2. **Plaintext HTTP Header Case Mutations:** For non-TLS TCP port 80 traffic, the parser searches for standard HTTP verbs (`GET`, `POST`, `CONNECT`). It rewrites HTTP header fields using mixed capitalization (e.g., `Host:` becomes `hOsT:`, `Connection:` becomes `cOnNeCtIoN:`) and adjusts spacing around colons to bypass filtering rules.

### 3.2 Userspace Raw Handshake Injection (paqet mode)
When `paqet` mode is active, the engine bypasses the kernel's default TCP 3-way handshake:
* **Outbound Synthesis:** The engine uses raw sockets (`IPPROTO_RAW`) to craft custom IP/TCP headers with random sequence numbers and injects them directly into the network.
* **Kernel Reset Suppression:** The local OS kernel, unaware of userspace socket negotiations, tries to send a Reset (`RST`) packet when it receives a reply. To prevent this, LumiNet dynamically installs firewall filters:
  * **Linux:** Automatically appends drop rules via `iptables`:
    ```bash
    iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
    ```
  * **Windows:** When a trusted operator-supplied WinDivert runtime is present, opens a `WinDivert` handle with filter string `outbound and tcp.Flags & 0x04` and discards matching outbound reset frames inside the event loop. WinDivert is not bundled by the repository or Windows release artifact.

---

## 4. Netrix KCP/UDP Transport Obfuscation

The Netrix transport protocol runs KCP over UDP connections to scramble traffic fingerprints and bypass UDP filters:

```
Outgoing App Data
       │
       ▼
 ┌───────────┐
 │   KCP     │  <── Segment queueing, congestion control, window pacing
 └─────┬─────┘
       │ [Raw Segment Payload]
       ▼
 ┌───────────┐
 │NetrixConn │  <── Compression framing (LZ4 / Zstd) & Jitter Injection
 └─────┬─────┘
       │ [Compressed + Padded Jitter Packet]
       ▼
 Outbound UDP Socket
```

### 4.1 Frame Compression Structure
The `NetrixConn` layer wraps the output stream and applies block compression:
* **Payload Evaluation:** Pays loads are evaluated before transmission. Payloads smaller than 1024 bytes skip compression to avoid metadata overhead.
* **Compression Headers:** Payloads larger than 1024 bytes are compressed using Zstandard (`zstd`) or LZ4. The outgoing packet is structured as follows:
  * **Byte 0:** Compression Type Flag (`0x00` for Raw, `0x01` for LZ4, `0x02` for Zstd).
  * **Bytes 1-4:** Big-endian uint32 representing the uncompressed payload size.
  * **Bytes 5+:** Compressed payload byte array.

### 4.2 Timing Jitter Injection
To break statistical packet-timing analysis (which firewalls use to detect VPN tunnels), `NetrixConn` processes outbound packet writes through a randomized queue:
* A jitter delay is calculated dynamically for each packet using a uniform distribution (between `5ms` and `20ms`).
* The packet is queued in a background thread and sent only after the jitter delay expires.

---

## 5. Build Troubleshooting & Cross-Compilation

### 5.1 CGO Linker Reference Errors
**Error:** an undefined Rust symbol or missing static archive during a host CGO build.
* **Cause:** the Cargo archive/native link metadata was not resolved for the selected profile/target, or the private ABI declaration drifted from Rust.
* **Resolution:** run `python3 scripts/checks/check_lumicore_abi.py` and `python3 scripts/checks/lumicore_link.py --profile <debug|release> [--target <triple>]`. Do not patch the failure with a copied archive or handwritten platform library list.

### 5.2 Threading Safety Warnings
**Error:** `go vet` reports duplicate mutex states.
* **Cause:** Struct values containing sync elements (like `sync.RWMutex`) are being copied directly.
* **Resolution:** Never copy struct instances that embed sync primitives. Implement explicit cloning methods that copy only the primitive data fields and leave the synchronization elements uncopied:
  ```go
  func (orig *JobConfig) SafeClone() *JobConfig {
      orig.mutex.Lock()
      defer orig.mutex.Unlock()
      return &JobConfig{
          Target: orig.Target,
          Port:   orig.Port,
          // Do not copy sync.Mutex
      }
  }
  ```
