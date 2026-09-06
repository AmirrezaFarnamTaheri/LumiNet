# Post-refactor-227 architecture

## Scope

Post-refactor-227 is a one-donor successor to immutable post-refactor-226. The new donor is `sni-spoofing-rust`; its 50 files are evidence, not a new product/runtime authority. The cumulative evidence universe is 53 donors, 3,810 donor surfaces, 25,821 definition records, and 297 module/subtree groups.

## Target-native result

### Exact connection evidence

The existing Go raw-packet owner remains `runtime/proxy/evasion_divert*`. Its captured-SYN registry is now keyed by the full TCP four-tuple, expires observations after 30 seconds, is capped at 4,096 entries, and supports atomic consume/clear. Out-of-window injection consumes fresh exact-flow SYN evidence rather than sharing a port-only sequence across unrelated flows.

### Canonical TLS decoy construction

`internal/networking/tlsdecoy` is the single Go owner for bounded fake TLS ClientHello construction. It validates ASCII DNS SNI up to 219 bytes and emits a 517-byte padded ClientHello. Both diagnostics and the live tunnel call this owner. The Rust evasion implementation mirrors the corrected 517-byte layout but remains static-only in this environment.

### Handshake evidence plane

`diagnostics.BuildSNIDecoyHandshakePlan` models SYN, SYN-ACK, third ACK, fake injection, server ACK, and RST evidence. It computes expected real/fake sequence values and relay readiness but performs no packet capture or injection. This is deliberately a planner: the current live target capture path does not observe the complete server confirmation lifecycle required to claim donor-equivalent relay gating.

### Product/API placement

The authenticated `/api/system/sni-decoy-handshake-plan` route exposes the read-only planner. Operations owns the UI surface. UI state is non-authoritative.

## Superseded donor-shaped authorities

The donor proxy/listener/relay runtime, Xray parser/runtime, mutable downloader/installer, bundled binaries, duplicate AF_PACKET/WinDivert backends, and macOS BPF runtime are not introduced as parallel owners. Linux/Windows raw ownership stays in LumiNet. macOS BPF is reference-only pending Darwin execution evidence.
