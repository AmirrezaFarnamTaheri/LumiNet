# LumiNet domain language

This glossary names the architectural concepts that have a single owner in the current system. Use these terms in code, tests, documentation, and future architecture reviews.


- **Source root** — `src/` is the sole root for live application and shared-package source. Tooling, docs, governance evidence, tests, deployment assets, labs, and third-party reference material remain outside it.
- **Dependency band** — one daemon-internal architectural layer under `src/apps/daemon/internal/`. Bands are ordered from deepest implementation to outer adapter; cross-band imports may point only downward, so folder placement communicates dependency direction.
- **Folder context** — a local `.context` file that explains a source folder's purpose, contents, interface/dependencies, invariants, and child ownership. It is navigation/architecture metadata, not a changelog and not generated product content.
- **Governance authority** — the machine-facing ABI, preservation, and provenance records under `governance/conductor/`. Validator modules discover their canonical files from repository root; command, CI, and compatibility callers pass policy or explicit overrides rather than duplicating authority paths.
- **Repository tooling surface** — the small direct human-facing interface documented by `scripts/README.md`. Other top-level tooling files are implementation helpers and require a live Make/CI/script caller; repository truth is owned once and consumed through release admission rather than duplicated in workflows.
- **Release admission** — the single compiler/test/truth decision that must pass before tag artifacts can be built or published. CI and release consume the same admission seam, and platform packaging consumes artifacts produced by that admitted verification rather than rebuilding unverified equivalents.
- **Windows packet dependency** — WinDivert-backed raw packet injection is conditional on an operator-supplied trusted runtime. WinDivert is not fetched, tracked, or bundled by current LumiNet delivery; startup fails closed when it is unavailable.
- **Lab archive** — non-authoritative preserved source under `labs/`, grouped by stable package/domain identity rather than historical wave or copied source-tree scaffolding. Governance records retain origin and retirement reason; directory depth is kept only when it carries package, provider, test-fixture, or other real semantics.
- **Repository depth** — directory depth exists only when it encodes a real package, app, provider, build, test-fixture, ownership, or immutable-evidence contract. Namespace/category wrappers with one child and no independent interface are flattened; current runnable apps are direct peers under `src/apps/`.
- **Deep-module stop rule** — package count and LOC are not refactoring targets. Merge only when the deletion test removes an interface without spreading complexity; split only when the locality test can hide unrelated caller knowledge behind a coherent owner.
- **Daemon lifetime** — the caller-owned cancellation and shutdown path that starts, stops, unsubscribes, and joins daemon background work. Constructors do not create process lifetime implicitly.
- **Job intent** — the typed, validated description submitted to the jobs module. Execution-only credentials may exist in the in-memory intent but never in public or persisted job history.
- **Job history config** — the secret-safe serialized representation retained for history, restart accounting, and export. It is not an execution contract.
- **Host-network transaction** — the single snapshot → durable recovery record → apply → verify → commit/rollback protocol for machine-wide DNS, proxy, firewall, certificate, and TUN mutations.
- **Runtime engine** — a long-lived daemon-owned network runtime. Tor and Psiphon are the production adapters behind `internal/runtime/runtimecore`.
- **Proxy qualification** — an ephemeral Xray/sing-box test session that owns temporary core selection, process/config lifetime, progress, cancellation, and normalized results. It is intentionally not a runtime engine.
- **Evasion runtime** — the owner of evasion defaults, normalization, capability validation, redacted status snapshots, listener lifecycle, and internal dial policy.
- **Mobile binding adapter** — the gobind-compatible translation surface. It does not own separate runtime state, evasion defaults, secret visibility, or safety-policy truth.
- **Active scanner** — scanner behavior with a proven product consumer through the supported scan/session interface.
- **Preserved scanner corpus** — byte-preserved historical scanner code proven to have no active symbol, build-tag, registration, reflection, native, or platform consumer.
- **Telemetry truth** — rates derived from authoritative cumulative traffic counters; unknown values remain unknown rather than fabricated as zero; one WebSocket owner emits one JSON envelope per frame.
- **Terminal stream event** — the single Rust callback that ends FFI stream ownership and authorizes the Go host to close the channel and release callback memory.
- **Native dormant surface** — a compiled/exported Rust or FFI surface with no repository production consumer. It may not gain a consumer until its implementation is verified; retirement that changes Rust modules or ABI requires the native Cargo/ABI/CGO gate.
- **Capability truth** — public status must distinguish implemented/available behavior from degraded, unavailable, simulated, stubbed, or unverified behavior.
- **Operational capability** — a control whose mutation crosses a real production runtime owner and is observable through that owner. Analysis-only, compatibility, simulated, or disconnected controls never report operational success.
- **Subscription ingestion** — the `internal/integrations/sub` owner for safe remote fetch, refresh lifetime, format detection, normalization, and profile metadata; canonical per-node semantics flow through `internal/networking/proxyconfig`.
- **Served route inventory** — the live Gin route set exposed by `GET /api/routes`, with workflow/capability/availability metadata derived from the same served surface. It is the authority for whether a route exists.
- **Retired active corpus** — internal source proven to have no product consumer after test, registration, reflection, platform, native, and non-Go checks. It is removed from active packages; uncertain external seams stay live and governed historical evidence may remain under `labs/`.
