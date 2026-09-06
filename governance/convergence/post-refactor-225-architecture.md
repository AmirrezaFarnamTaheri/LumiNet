# Post-refactor-225 architecture and ownership

## Scope and denominator

Post-refactor-225 is a target-native convergence over 23 newly supplied donors while preserving the immutable post-refactor-224 result. The cross-wave review therefore covers 38 donors, 2,461 donor surfaces, 9,511 extracted definitions, 202 subtree groups, 1,572 high-signal surfaces, and 159 UI/product surfaces. The current wave alone accounts for 1,548 files in 323 directory/subdirectory nodes, 7,255 definitions, and 1,133 semantic decisions. No implementation, test, configuration, script, deployment, or UI/product surface is allowed to remain repository-level-only.

## Responsibility planes

### Runtime authority plane

Existing runtime owners remain authoritative. Post-refactor-225 does not add a second DNS resolver, SMUX runtime, WireGuard device, Wintun driver wrapper, TUIC transport, update engine, subscription store, packet-injection engine, or durable event store. Runtime changes are limited to hardening the live owner or removing false/dormant authority.

- `src/apps/daemon/internal/runtime/proxy` remains the daemon proxy/runtime owner.
- `src/apps/daemon/internal/platform/system/wintun_windows.go` remains the live Wintun DLL/session owner.
- normal TUIC proxy outbound remains owned by the core-manager/QUIC path; the legacy raw-TCP covert TUIC path fails closed.
- `src/packages/lumicore/src/system/userspace_tun.rs` is the remaining Rust userspace translation owner after the print-only `tun_engine.rs` and `tun_nat.rs` facades were retired.
- config mutation remains single-owned by `foundation/config.Manager.Mutate`.

### Planning and evidence plane

New donor value that would otherwise duplicate authority is recomposed into bounded, read-only planning contracts under `internal/analysis/diagnostics`:

- SNI path lifecycle and active/reserve/drain recommendations;
- SNI gateway/deployment preflight;
- relay/STARTTLS design inspection;
- secret-bearing artifact admission/quarantine;
- DNS resolution transport/fallback/cache/ECS policy;
- multiplex session/capacity/padding policy;
- routing-artifact provenance;
- TLS fingerprint trial/reuse policy;
- service incident/maintenance policy;
- bounded queue/backpressure/export-failure policy;
- declarative network workflow composition;
- WireGuard peer/device/session readiness.

These contracts have no socket-opening, installer, downloader, route mutation, notification, queue mutation, key-store, or packet-capture authority.

### Protocol hardening plane

Donor state machines are used as differential oracles against existing owners:

- ClientHello/SNI extraction uses the canonical bounds-checked parser; pattern-only SNI discovery is rejected.
- TLS fragmentation operates on structurally valid ClientHello evidence and preserves complete record reconstruction.
- TUIC v5 command encoding enforces domain/u16 payload/fragment bounds and distinguishes “authentication frame written” from peer acceptance.
- WireGuard/WARP share-link parsing no longer fabricates missing key material.
- Wintun ring capacity and packet sizes are checked before the live adapter calls into the driver.
- userspace TUN translation rejects malformed or fragmented packets, keys flows by a full 5-tuple, evicts deterministically, and repairs checksums.

### Product plane

Read-only planning is placed in the product area where an operator naturally reasons about it rather than being stranded in a generic lab:

- DNS: resolver presets, DoH pool evidence, DNS resolution policy.
- Connections: endpoint dispatch and multiplex admission.
- Rules: routing-artifact provenance and offline L7 signature admission.
- Settings/WARP: ranked WARP scan evidence and non-authoritative export/copy.
- Health: incident/maintenance policy.
- Logs: local search/severity/export plus WebSocket backpressure counters.
- Profiles: bounded local profile/node search.
- Operations: generic convergence laboratory and advanced read-only planners.

UI state does not own runtime state. Applying configuration continues through the existing authenticated API owners.

## Retired false or duplicate authority

Post-refactor-225 explicitly removes surfaces whose existence overstated target capability or duplicated a stronger owner:

- zero-consumer print-only Rust `tun_engine.rs`;
- zero-consumer print-only Rust `tun_nat.rs`;
- dormant Go MITM relay with arbitrary byte mutation callback;
- duplicate zero-consumer Wintun DLL wrapper `wintun_go.go`;
- zero-consumer insecure CDN scanner facade;
- zero-consumer insecure handshake scanner facade and its dedicated test;
- non-conformant raw-TCP “covert TUIC” execution path is fail-closed while normal TUIC/QUIC remains supported.

## Mutation ownership

Automatic mutation retry was requested again for this wave, but the correct implementation already exists from post-refactor-224. It is intentionally not duplicated. The invariant remains: three attempts by default, hard maximum eight, a fresh authoritative snapshot on every retry, only revision conflicts are retried, and an explicit `ExpectedRevision` forces one attempt.

## Cross-wave composition

The immutable 224 semantics remain inputs to 225 rather than being rewritten. Examples of higher-level recomposition across waves include:

- 224 load-balancer/L7MP endpoint evidence + 225 health/pool semantics -> Connections dispatch planning;
- 224 LuCI DoH provider catalogue + 225 DNS policy -> DNS preset discovery and DoH pool evidence;
- 224 L7 pattern corpus + 225 routing/provenance discipline -> Rules admission surfaces;
- 224 log-demultiplexer/backpressure evidence + 225 product audit -> Logs filtering/export/backpressure visibility;
- 224 KCP policy and relay polling remain unchanged and are rechecked as historical owners.
