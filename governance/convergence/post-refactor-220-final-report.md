# LumiNet post-refactor-220 cross-40 convergence

## Executive result

Post-refactor-220 moves LumiNet from feature-by-feature peer absorption to a higher-order convergence model over the current **40-project universe**: the LumiNet target plus **39 uploaded donor archives** from the post-refactor-160 and post-refactor-180 waves. The two immutable historical surface matrices account for **18,517 donor file/symlink surfaces**. This pass reopens prior held/reference dispositions and promotes only the value for which a single target-native authority can now be proven.

The dominant new planes are:

1. canonical cross-runtime flow observation and owner-delegated close;
2. passive daemon-wide network epochs and handoff history;
3. derived provider/protocol/path network intelligence;
4. local loss-aware multi-format profile compatibility conversion;
5. declarative detour-safe profile shaping;
6. strict generated-output semantic re-ingest proof;
7. credential-redacted, operator-confirmed interrupted-job recovery with durable lineage;
8. a unified read-only Capability & Coverage Center that separates registry availability, native linkage, runtime-owner participation, passive network observation, and provider-corpus freshness.

The pass also preserves the mandatory post-refactor-160 **automatic configuration mutation retry** contract and fixes a VLESS URI security downgrade discovered by the new round-trip oracle.

## Why this is a convergence rather than a feature pile

Each promoted capability closes a previously identified prerequisite:

- Yacd/Throne/IPRadar connection UX was held until one canonical cross-runtime flow ledger existed. It now does.
- tailscale-rs netmon was held until observation could be separated from route/network mutation authority. It now is.
- Scrapling scheduler restore was held until reconstructibility, credential persistence and idempotent replay were explicit per job. Recovery is now a typed new-execution contract, not boot replay.
- subconverter conversion breadth was held behind the existing canonical profile owner. It now operates as a pure transformation/export plane above `ProxyConfig`, not as another parser daemon.
- V2RayDAR's runtime validation lesson becomes an always-available local re-ingest oracle first, with external runtime verification remaining optional release evidence rather than a second runtime authority.

## Cross-runtime flow and path plane

`foundation/flowregistry` is the canonical observation contract. Runtime owners declare `Visible`, `Closeable`, byte-counter, process-attribution and destination-metadata coverage before any flow can be registered. The registry assigns stable flow IDs, deep-copies mutable metadata, keeps bounded capacity, tracks upload/download monotonically, separates active/closing lifecycle, and delegates close to the owner outside the registry lock. Failed close restores the record when appropriate. Oversized bulk close is rejected before any callback.

The evasion SOCKS path and stateful relay transports publish real lifecycle and confirmed byte movement. Runtimecore declares negative coverage for long-lived runtimes that cannot yet supply truthful per-flow state. This is intentionally better than a dashboard that equates an empty local table with no host connections.

`platform/system.NetworkMonitor` adds a passive network epoch. Its fingerprint includes interfaces, addresses, MTU, hardware/link identity, flags and inferred IPv4/IPv6 egress. History/subscribers are bounded and revisions advance only on meaningful change. Flow creation stamps the current epoch.

`analysis/netintel` then derives pre-handoff/unknown-epoch flows, owner path state, provider/protocol distributions, byte totals, egress context, handoff history and provider-corpus freshness from existing local evidence only. It does not issue DNS, GeoIP, scan, process, route, firewall or runtime operations.

The Connections UI exposes all of this with search/filter/detail and explicit selected close. Coverage gaps remain visible. There is no close-all shortcut and the UI owns no flow state.

## Capability and coverage truth plane

The existing capability registry is now composed with the new flow/network evidence rather than left as a binary feature list. `GET /api/capabilities` schema v4 reports five independent truth dimensions: registered capability availability, native-core ABI linkage, flow-owner participation and counters, passive network-monitor state/revision, and provider-corpus readiness/freshness. The API is read-only and derives each dimension from its canonical owner.

The new **Capability & Coverage Center** consumes that typed response. It deliberately shows partial flow coverage, stopped or errored network observation, stale provider data, and unavailable native linkage separately. A green capability badge cannot mask a missing runtime owner or stale corpus. This is a second-order product synthesis of Yacd/Throne/IPRadar-style status discoverability with LumiNet's stricter target-native evidence model.

## Compatibility and transformation plane

`ConvertConfigs` supports:

- plain URI list;
- Base64 subscription;
- versioned LumiNet canonical JSON;
- Clash Meta YAML;
- sing-box JSON.

Every conversion carries exact source/emitted/unsupported/lossy/warning evidence. It preserves advanced canonical semantics where representable, including TLS/Reality, WebSocket/gRPC/http-upgrade, multiplexing, Hysteria2, TUIC, AnyTLS, Juicity, DNSTT and WireGuard/AmneziaWG extensions. Sing-box detour chains are bounded, top-level, unambiguous and acyclic.

`TransformConfigs` provides bounded local include/exclude regexes, protocol allowlisting, rename, semantic dedupe, deterministic sorting and limits. It preserves/rebinds detour graphs and fails closed if filtering/limiting would orphan a hop. Donor script execution, remote includes and arbitrary filesystem access are intentionally not carried over.

The strict post-export oracle is the crucial second-order improvement. `ValidateRoundTrip` re-ingests the generated representation through LumiNet and compares semantic node state, cardinality and top-level detour relationships. Strict conversion fails if generated output cannot be locally reconstructed without drift. This caught a concrete serializer defect during this pass: explicit VLESS `Security=tls` or `reality` could previously lose to a stale/false `TLS` boolean and emit `security=none`. The serializer now honors explicit security mode before boolean fallback; URI/Base64 re-ingest tests pass.

The Profiles Compatibility Lab exposes transformation metrics, conversion evidence, local re-ingest proof, parser error and bounded node-level drift evidence. It never fetches URLs or modifies managed profiles.

## Interrupted-job recovery plane

Recovery first hardened persistence. Proxy-test job history previously serialized the full intent, potentially retaining credential-bearing proxy URIs/addresses. Persisted config is now a transport-safe preview and legacy rows are scrubbed on read; the raw secret remains in transient in-memory intent only.

Only credential-free observational interrupted jobs with an explicit reconstruction path are recoverable. ProxyTest, provisioning/deployment and other consequential/secret-bearing work is not reconstructible. `GetRecoveryInfo` reports policy, reconstructibility, requeue availability and active descendant. `RequeueInterrupted` holds a serialization gate, refuses an active descendant, creates a new queued job with `recovered_from`, and leaves the source immutable. The API requires `confirm=true`; normal JobManager admission starts the new execution. There is no initialization hook that automatically replays work.

The Operations UI follows the same authority model: inspect first, show why a job can/cannot be reconstructed, show an active descendant if present, then require explicit confirmation to create the new execution.

## Small superseding peer fragments retained

The deeper audit did not stop at planes. Throne's AnyTLS implementation exposed idle-session check interval, idle timeout and minimum idle-session semantics missing from the canonical target model. Those fields now survive parser aliases, URI generation and supported conversion targets. The strict conversion oracle itself then found the VLESS security downgrade noted above. These are deliberately adopted despite being much smaller than their donor applications because they supersede target semantics at the correct granularity.

## Automatic mutation retry remains mandatory

The post-refactor-160 configuration authority was re-audited after all new planes. `Manager.Mutate` still uses fresh-authority intent replay only for server-owned mutations after `ErrRevisionConflict`. Default attempts remain 3, hard cap 8, and explicit expected revision forces one compare-and-swap attempt. The HTTP adapter remains centralized. No new flow, network, conversion or recovery path mutates configuration through a parallel write authority or places runtime side effects inside the retried intent.

## Explicit boundaries after the second-order audit

The project does not become stronger by literally embedding every unrelated peer product. The re-audit leaves these as explicit non-promotions:

- arbitrary host process kill based on observed connections;
- a second generic firewall/block-list mutator;
- raw fake-TCP/SNI injection services;
- legacy obfuscated-OpenSSH protocol fork;
- multi-user Xray reseller/server administration;
- general OIDC identity-provider service;
- a second GTK UI/toolchain;
- scraped public proxy configurations as trusted product data.

These are not skipped peer directories. Their source surfaces remain accounted in historical matrices and their current resolutions are in `post-refactor-220-cross-wave-accountability.csv`. Their useful lessons (coverage truth, identity/authority separation, supply-chain distrust, process-control boundaries) are retained as design constraints.

## Evidence artifacts

The source tree contains:

- `post-refactor-220-baseline-files.csv` — exact pre-220 post-180 source snapshot;
- `post-refactor-220-cross-wave-accountability.csv` — all 40 project rows and historical links;
- `post-refactor-220-adoption-ledger.csv` — fine post-220 value-unit decisions with exact peer hashes and target/test anchors;
- `post-refactor-220-high-level-plane-audit.csv` — promotion/rejection decisions above primitive scale;
- `post-refactor-220-peer-synthesis.md`;
- `post-refactor-220-omission-audit.md`;
- `post-refactor-220-validation.md`;
- `post-refactor-220-summary.json`;
- `post-refactor-220-target-delta.csv` — generated at source freeze;
- `scripts/checks/check_post_refactor_220_convergence.py` — source/evidence/exact-delta gate.

## Validation boundary

Focused changed foundations have executable isolated evidence using exact current source under the available Go 1.23 standard library environment: flow registry 9 tests, network monitor 6, network intelligence 2, recovery 4, conversion/transformation/round-trip 15, plus focused VLESS security re-ingest. The source UI/API characterization has **41 checks** and the ten touched capability/flow/conversion/recovery/router TS/TSX surfaces transpile with TypeScript 5.8.3. The repository Go declaration checker sees **1,557 files with zero syntax errors and zero duplicate active declarations** across Linux/Windows/macOS/Android selections.

The complete canonical repository verifier was executed on this expanded source in two bounded bands because the sandbox command-duration ceiling interrupts the monolithic Make target. Every command in `make verify-repo` completed successfully when resumed at the exact unexecuted boundary: source/context/topology/ownership, all historical convergence gates through post-refactor-220, route/platform/native truth, FFI checks, convergence validators, peer convergence and repository audit. The only audit output is the inherited warning that no local Android Gradle wrapper is checked in because CI/release provisions Gradle 9.5.0.

Full Go 1.26 workspace, Rust/Cargo, Android Gradle and dependency-backed frontend build claims are not manufactured in an environment that lacks those toolchains/dependencies. Archive/member/hash and clean-extraction verification are release-stage evidence and are recorded in the release receipt rather than retroactively modifying the frozen source after packaging.
