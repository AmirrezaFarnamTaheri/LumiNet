# Post-refactor-223 target architecture

## Responsibility planes

- **Host-network plane:** `HostNetworkManager` remains the sole durable owner of host proxy snapshots/routes. The evasion runtime may request a route but must release the exact owned route before bridge teardown.
- **Proxy runtime plane:** `CoreManager` remains the runtime process owner. The HTTP→SOCKS bridge is a compatibility adapter; `SubscriptionRuntime` owns at most one explicitly activated subscription node and never mutates system proxy state.
- **Subscription source plane:** `ProfileService` owns subscription source metadata/refresh and a session-scoped `NodeCatalogue`; source URLs and node credentials never enter general operator views.
- **Scanner/diagnostic plane:** bounded scanner planning, strict REALITY TLS evidence, transport truth and DNS transport-integrity planners are observational/read-only. They do not dial or mutate routes except where their named scanner explicitly performs its established probes.
- **DNS tunnel plane:** existing framing/runtime remains authoritative. Reliability presets/FEC/ARQ/resolver tiers are advice appended to the existing planning API.
- **Provisioning plane:** DNS delegation preflight decides whether provisioning may proceed; remote VPS publication uses one managed-generation transaction and rollback owner.
- **Mobile plane:** exactly one Android `VpnService` owns TUN establishment/socket protection. `LumiNetTileService` is an observer/controller only.
- **Native plane:** LumiCore remains the sole Rust native core/ABI. Go async bridging and raw Rust FFI boundaries are hardened without introducing a second native registry/runtime.
- **Operator plane:** Control UI remains non-authoritative. New cards expose evidence/plans; command aliases only navigate to existing sections.

## Cross-plane contracts

- Exact route/session ownership IDs before destructive stop/release.
- Bounded request/evidence arrays and string sizes at public planners.
- No plaintext subscription credentials in API/UI node views.
- Stable structured failure kinds separate from redacted human diagnostics.
- Read-only planners never acquire transport/resolver/system-proxy authority.
- State transitions fail closed when exact ownership or recovery evidence is uncertain.
