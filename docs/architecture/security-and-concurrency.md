# 🔒 LumiNet Security Model, Concurrency Safeguards, and Data Protection

This document outlines the security architecture, concurrency safety standards, and data protection controls implemented across the LumiNet daemon and core libraries.

---

## 1. Local Control Plane IPC Authorization

LumiNet restricts the local daemon command and control plane endpoints to avoid local privilege escalation risks.

### 1.1 Unix Domain Sockets (UDS)
On Unix-like platforms (Linux, macOS, Android), the daemon communicates via Unix Domain Sockets:
* **Permissions Enforcement**: The socket file descriptor is restricted to `0600` permissions via filesystem ACLs.
* **Bypass Verification**: Unix domain socket connections bypass API key verification because file ownership checks guarantee that only the owner process can connect.

### 1.2 Windows TCP Loopback Authentication
Since Windows does not consistently enforce file-level permissions on named pipes or loopback sockets, the Windows control plane listens on loopback TCP (`127.0.0.1:10088`):
* **API Key Handshake**: The loopback TCP listener requires authorization on connection boot.
* **Verification Loop**: 
  1. The connecting client must send the session API key as a plaintext line immediately upon connection.
  2. The daemon verifies the key using a constant-time comparison helper (`subtle.ConstantTimeCompare`) against the active session key (`effectiveKey`).
  3. If unauthorized, the connection is immediately aborted, preventing local TCP port hijacking.

---

## 2. Concurrency Safety and Mutex Copying Rules

To ensure performance under high parallel loads (e.g. subnet sweeps), Go structs that embed synchronization structures (`sync.Mutex`, `sync.RWMutex`) must follow strict concurrency rules.

### 2.1 Mutex Copying Prevention
Copying a mutex duplicates its locking state, leading to deadlocks or memory corruption. The compiler vet suite blocks code that copies lock primitives. 
* **Safe Cloning Rule**: All Go structs containing mutexes must implement a custom `.Clone()` function that duplicates the primitive data values while leaving the sync structures initialized as new zero-values:

```go
func (orig *Job) Clone() *Job {
	orig.mu.RLock()
	defer orig.mu.RUnlock()
	return &Job{
		ID:        orig.ID,
		Type:      orig.Type,
		Status:    orig.Status,
		Progress:  orig.Progress,
		CreatedAt: orig.CreatedAt,
		// mu (sync.RWMutex) is left at its zero-value
	}
}
```

---

## 3. Log Sanitization & Redaction Engine

To prevent leakage of sensitive credentials, tokens, or PII into standard console outputs or SQLite transaction records, all string logs are filtered by a centralized redaction engine.

### 3.1 Regular Expression Filters
The redaction engine ([redact.go](../../src/apps/daemon/internal/foundation/redact/redact.go)) matches sensitive patterns:
* **Query Parameters**: Capitalization-agnostic filtering of `pass=***`, `password=***`, `token=***`, `key=***`, `api_key=***`.
* **Proxy URIs**: Trojan, VMess, VLESS, and Shadowsocks connection strings are cleaned (e.g., `vless://[REDACTED]@host:port`).
* **OAuth Tokens**: Authorization headers (e.g., `Bearer ***`, `Basic ***`) are truncated.

---

## 4. DPAPI Config Encryption

LumiNet protects persistent configuration files against offline credential harvesting.

* **Windows DPAPI**: On Windows target platforms, sensitive properties inside `config.json` (such as proxy node passwords, dynamic DNS tokens, and CAPTCHA api keys) are encrypted utilizing the Windows Data Protection API (DPAPI) via system cryptographic libraries.
* **Encryption Scope**: The cryptopack encrypts payloads bound to the local user account, ensuring that other user profiles or offline disk copy operations cannot decrypt target credentials.
* **Pure-Go Fallback**: Cross-platform instances default to volatile secure random AES-GCM keys if DPAPI is unavailable.
