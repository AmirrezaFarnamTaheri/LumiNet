# Post-refactor-224 target architecture

## Responsibility planes

- **Proxy/KCP runtime plane:** the existing Go proxy runtime remains the sole KCP+SMUX owner. `kcppolicy.Resolve` supplies bounded advice and explicit overrides to both dialer and listener paths; upstream `kcp-go/v5` remains the implementation owner.
- **Endpoint and mesh evidence plane:** diagnostics planners interpret latency, loss, health, capacity, circuit, load and stickiness. Secondary signals may reorder only near-equivalent endpoint candidates; stale/unhealthy mesh edges are excluded and degraded edges receive only a bounded penalty.
- **DNS evidence plane:** `BuildResolverPoolPlan` validates HTTPS resolver candidates, bootstrap IPs, canary/circuit evidence and fallback ordering. It is read-only and never contacts or installs a resolver.
- **Offline signature plane:** L7 expressions are bounded, RE2-compiled and hashed offline. This plane does not inspect live packets or install classifiers.
- **Declarative traffic-profile plane:** Marionette-derived value is represented as a bounded state/profile analyzer and presets. It cannot execute plugins, commands, scripts, processes or network actions.
- **Routing corpus plane:** routing inputs are normalized, hashed and audited for provenance/duplicates/missing includes. Stable target-native policy presets do not contain copied mutable donor lists.
- **Relay plane:** existing GSA and generic HTTP serverless transports share one client-controlled adaptive polling state machine. Empty successful polls back off from 200 ms to 4 s; traffic or a local write restores interactive cadence. Transport-error retry remains a separate state machine.
- **Configuration authority plane:** `foundation/config.Manager` remains the sole local configuration CAS owner. Server-owned mutation intents can retry revision conflicts from fresh snapshots; explicit client revisions are never replayed.
- **Transient event plane:** the existing WebSocket hub remains bounded and non-durable. Broadcast drops and slow-client disconnects are monotonic observability counters; persisted jobs remain the durable source of truth.
- **Operator plane:** authenticated Operations surfaces expose endpoint/KCP/DoH/L7/traffic/routing planning and reliability evidence. UI state remains non-authoritative.

## KCP crypto boundary

Legacy KCP cipher identifiers/default behavior are unchanged. The exact pinned `github.com/xtaci/kcp-go/v5 v5.6.72` source exposes `NewAESGCMCrypt`; post-refactor-224 recognizes `aes-gcm`, `aes-gcm-128`, `aes-gcm-192`, and `aes-gcm-256` only as explicit opt-in choices. Full daemon compilation of that path is environment-blocked in this sandbox because the repository requires Go 1.26 while the available local toolchain is Go 1.23.2.

## Relay

The donor's stateful server-held `wait_ms` long poll is not claimed or emitted. LumiNet controls only client polling cadence because it does not own the donor server protocol.

## Cross-plane invariants

1. Evidence/planning signals never create runtime or host-network authority.
2. A secondary endpoint strategy cannot promote a materially worse candidate across the existing five-point quality band.
3. Negative health evidence can exclude or penalize; it cannot create eligibility.
4. Mutation retry is bounded and revision-conflict-only; external/irreversible actions remain under their existing remote safety executor.
5. WebSocket delivery remains transient; job persistence remains authoritative.
6. Donor executors, installers, daemons, eBPF fast paths, shellcode, stack spoofing and live credential corpora do not enter target authority.
