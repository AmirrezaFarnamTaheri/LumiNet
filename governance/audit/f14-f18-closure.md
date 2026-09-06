# F-014–F-018 closure

## F-014 — cross-platform Go declaration integrity

**Status:** verified.

The dependency-free checker remains authoritative and is wired into `make verify-repo`. On the current tree it parsed 1,516 Go files with zero syntax errors and found zero duplicate active top-level declarations for Linux/amd64, Windows/amd64, Darwin/amd64, and Android/arm64 selections.

## F-015 — SSH server identity

**Status:** verified.

Both live SSH clients now require an explicit OpenSSH `SHA256:` host-key fingerprint. `platform/sshtrust` parses/canonicalizes the expected 32-byte digest and supplies one constant-time verification callback. Provisioning and covert SSH tunnel configuration fail closed when the fingerprint is absent, malformed, or does not match the presented server key. No live `ssh.InsecureIgnoreHostKey()` path remains.

Migration: callers of provisioning and SSH covert mode must provide `ssh_host_key_sha256`. This value is server identity evidence, not a credential.

## F-016 — privileged Docker bootstrap provenance

**Status:** verified.

The mutable `get.docker.com | sh` bootstrap is removed. Automatic bootstrap is deliberately limited to apt-based Debian/Ubuntu hosts: refresh signed repository metadata, resolve the `docker.io` candidate, validate the candidate string, install that exact version, then verify `docker --version`. Other hosts fail closed and require Docker to be preinstalled.

## F-017 — Rust legacy FFI ownership/error envelope

**Status:** implemented; statically validated.

The 42 exported C functions preserve their normalized names, arguments, and return types. Legacy JSON raw pointers are copied into owned Rust strings immediately, null/UTF-8/JSON failures are distinct, pointer-returning legacy calls share a panic envelope, asynchronous entry points admit raw inputs before dispatch, and the arbitrary-lifetime `c_str_to_str<'a>` helper is removed. Unsafe legacy exports have explicit `# Safety` contracts.

Rust/Cargo/Miri are unavailable in this environment, so compiled/runtime Rust equivalence is not claimed.

## F-018 — polling relay connection semantics

**Status:** verified.

HTTP and GSA polling adapters now share one deep connection-state module owning bounded TX/RX buffering (1 MiB each), real read/write deadlines, close/error wakeups, in-flight accounting, copied rollback ordering, and cancellation-aware capped outage backoff. Successful communication resets retry debt. The `net.Conn` interface remains the caller test surface.
