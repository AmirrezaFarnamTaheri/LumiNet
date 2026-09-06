# Post-refactor-222 architecture and composition map

## Promoted target-native planes

### Peer identity and discovery planning

Owner: `internal/analysis/peerdiscovery` with an authenticated read-only API adapter and Operations UI.

Inputs are operator-supplied node IDs, literal IPv4 endpoints, optional bounded CIDR deny prefixes, a result bound, and a read-only snapshot of existing runtime trust. The plane owns no socket, route, peer persistence, DHT crawler, tracker or trust mutation. It combines BEP42 identity binding, canonical public-address policy, duplicate/self rejection, local deny policy, shared-address evidence, exact XOR ordering and bounded output.

### Endpoint continuity and diversity

Owner: `internal/analysis/diagnostics` endpoint pool planner.

Existing success/quota/latency evidence remains authoritative. Stealthspanner contributes jitter/loss as penalty-only evidence; EDtunnel contributes continuity/failover inspiration. Previous success can only move within a five-point quality band. Scope-based diversity is deterministic and limited to near-equal bands.

### Health and diagnostics product plane

Owner: Control UI `Health` page as a non-authoritative projection.

It composes existing readiness, capabilities, passive network state and UI transport health. The diagnostic export is allow-listed and structural: no raw logs, configuration bodies, API keys, hardware addresses, interface addresses, credential-bearing URLs, free-form readiness messages or raw source/network errors.

### Operator navigation and appearance

Owner: Control UI.

A canonical navigation registry feeds sidebar and command palette. Fuzzy ranking is deterministic; recents are bounded and validated. Appearance is local System/Light/Dark state with early initialization and cross-tab synchronization. Neither surface has daemon authority.

### Subscription deep-link admission

Owner: canonical subscription integration/parser plus an authenticated inspect-only API adapter and Profiles UI.

Marz contributes the low-friction one-tap import concept. LumiNet rederives it as `luminet://import` and deliberately removes implicit authority: the URI is bounded, accepts only `url` and optional `name`, requires the canonical managed-profile HTTPS policy, rejects credentials, and only returns a proposal. Inspection performs no network fetch, persistence, refresh, activation, route mutation or configuration write; the operator must explicitly create the profile through the existing owner.

### Signed update publication hardening

Owner: `foundation/updateadmission`.

Verified staged files are regular-file confined; contents are synchronized; Unix publication uses atomic rename-overwrite and synchronizes the parent directory. Platform-specific replacement semantics are explicit.

### Mutation retry consolidation

Owner: `foundation/config.Manager.Mutate` for configuration and `foundation/remoteaction.Executor` for external side effects.

The generic 221 Rust retry helper is removed. This avoids two retry/state authorities and preserves different correctness contracts for CAS-only configuration changes versus remote side effects requiring reconciliation.

## Superseded donor-shaped subsystems

Whole donor runtimes are not retained when a stronger LumiNet owner already exists: EDtunnel Cloudflare proxy runtime, Nabzram Python/TinyDB/Xray backend, Marzban-node RPC/process wrapper, VpnDad iOS PacketTunnel runtime, stealthspanner provider downloader/firewall helper, TaoConnect blockchain-validator lease model, cdin editor/plugin/filesystem shell, Kloak browser-OS/mail/social/media suite, HDS multi-user Flask identity stack, and mission-improbable device flashing pipeline.

## Cross-plane invariants

1. UI is non-authoritative.
2. Observational trust/risk never grants identity or bypasses validation.
3. Remote targets pass canonical public-address admission when the target contract requires public Internet reachability.
4. Retries are bounded and owner-specific; external effects are not replayed by generic CAS retry.
5. Secrets remain referenced/redacted outside dedicated secret owners.
6. Generated/obfuscated artifacts are not source of truth when authoritative source exists.
7. Every promoted remote/network action has explicit resource bounds and cancellation/recovery semantics appropriate to its owner.
8. Deep links, imported UI state and local preferences may propose or prefill canonical state but never become an implicit write or network-action authority.
