# Post-refactor-220 cross-40 peer synthesis

## Scope and decision model

This pass treats the two uploaded peer waves as one convergence universe: **LumiNet plus 39 donor archives (40 projects)**. The immutable post-refactor-160 and post-refactor-180 surface matrices account for **18,517 donor file/symlink surfaces**. Post-refactor-220 does not re-count those same files as new evidence; it re-opens every previous disposition, especially held/reference-only items, and asks whether new target prerequisites allow a stronger composition.

The governing rule remains target-native supremacy: peer packaging is disposable. A feature is promoted only when LumiNet has one coherent owner for authority, persistence, lifecycle, failure, recovery, observability and operator semantics. Otherwise the peer remains reference, guardrail, superseded, or rejected-with-reason even when its UI or local implementation is attractive.

## Major second-order promotions

### 1. Connection UX became a canonical cross-runtime flow plane

Post-refactor-180 intentionally held IPRadar, Yacd and Throne connection views because LumiNet only had engine-local session maps. This pass adds `foundation/flowregistry` as the single observation contract. Runtime owners must declare exactly which fields and close authority they can provide before registering a flow. Real byte counters and owner-delegated close are used where available; missing owners are represented as negative coverage, not as an empty connection list. The evasion SOCKS runtime and stateful relay transports publish actual flow lifecycle/counters. Tor, Psiphon, SSTP and IKEv2 explicitly declare that per-flow visibility is currently unavailable.

The Connections product surface is downstream of that registry. It supports search, owner filtering, per-flow detail, selected bounded close with confirmation, network-epoch context and provider attribution. It deliberately has no host-wide `close all` button. Oversized bulk close rejects the entire request before any owner callback, preventing a partial-prefix close that the operator might mistake for complete execution.

### 2. Tailscale-style netmon became a passive network-epoch owner

The previously held `tailscale-rs` netmon value is rederived as `platform/system.NetworkMonitor`. Snapshots include interface index/name, addresses, MTU, hardware/link identity, flags and inferred IPv4/IPv6 egress interface/local address. A fingerprint drives a monotonically increasing revision only on meaningful change. History and subscribers are bounded and slow subscribers are coalesced. Route inference is passive: it does not request a platform network, retain a radio/network lease, write a route, or issue application payload.

Flow records carry the network epoch at creation. This makes handoff analysis evidence-based: a flow can be classified as pre-handoff or unknown-epoch without rewriting its history or guessing from current UI state.

### 3. IPRadar/mylg/tailscale evidence became a derived network-intelligence plane

`analysis/netintel` combines only already-authoritative local evidence: flow registry snapshots/coverage, passive network epochs and the activated immutable provider longest-prefix corpus. It reports owner state, active/closing/pre-handoff/unknown-epoch flows, upload/download, provider/protocol distributions, active interfaces, egress context, recent handoffs and provider-corpus freshness. It performs no DNS lookup, remote GeoIP request, active scan, process execution, route mutation, firewall action or runtime mutation.

This is intentionally stronger than copying IPRadar's scanning/process-control surface: operators get the useful path picture without creating a second network or host-process authority.

### 4. Subconverter/V2RayDAR evidence became a compatibility and transformation plane

LumiNet retains one canonical `ProxyConfig` parser/model. On top of it, `ConvertConfigs` supports URI list, Base64 subscription, versioned LumiNet JSON, Clash Meta YAML and sing-box JSON. Every target reports emitted/unsupported/lossy/warning evidence. Advanced transport/TLS/Reality, multiplexing, Hysteria2, TUIC, AnyTLS, Juicity, DNSTT and WireGuard/AmneziaWG fields are carried where the target representation supports them. Sing-box detour relationships are resolved as a bounded acyclic top-level graph rather than flattened.

`TransformConfigs` adds local declarative shaping: bounded include/exclude regexes, rename rules, protocol allowlisting, semantic de-duplication, deterministic sorting and limiting. It clones inputs, rebinds retained detour references and rejects a filter/limit that would orphan a dependency. The donor's embedded scripts, remote includes and filesystem authority are not copied.

A second-order local round-trip gate now re-parses generated output and compares semantic node state, cardinality and top-level detour graph. Strict mode rejects parser failure or drift even when first-pass exporter bookkeeping reported no incompatibility. That oracle found a real target bug: VLESS `security=tls`/`reality` could be serialized as `security=none` when the legacy TLS boolean disagreed. The serializer now preserves explicit security mode first.

### 5. Scrapling-style recovery became typed explicit job lineage, not daemon auto-resume

The earlier guardrail correctly rejected generic scheduler replay because LumiNet jobs have different side-effect and secret semantics. This pass first fixes the prerequisite: persisted ProxyTest history no longer stores full credential-bearing proxy URIs/addresses and legacy history is scrubbed to a transport-safe preview.

Only a strict whitelist of credential-free observational interrupted jobs is reconstructible. `GetRecoveryInfo` explains the policy and active-descendant state; `RequeueInterrupted` creates a new job with durable `recovered_from` lineage. The source record is immutable. A serialization gate and store query prevent concurrent duplicate active descendants. The API requires `confirm=true`; the Operations widget inspects before it can ask the operator for a second confirmation. Nothing replays at daemon boot. ProxyTest, VPS provisioning, edge deployment and other secret-bearing/consequential work remain non-reconstructible.

### 6. Throne AnyTLS details were absorbed at the canonical model, not just the UI

AnyTLS idle-session check interval, idle timeout and minimum idle-session count are now canonical fields, parser aliases and URI/conversion semantics. This is a small peer fragment that superseded the target's previous incomplete representation and therefore is adopted even though the donor's broader desktop stack is not.

## Preserved earlier superior mechanisms

The deeper pass revalidated rather than duplicated post-160/post-180 mechanisms: bounded automatic configuration mutation retry; Android per-app VPN; passive Android underlay tracking; shared public endpoint admission; front-aware Tor bridge diagnostics; actual iperf3; evidence-bounded STUN mapping; validate-before-swap source refresh; bounded redirect/Retry-After; truthful traceroute; immutable provider LPM; real-handshake WARP jitter; declared IP-length parsing; and conflict-aware bounded IPv4 reassembly. No newly reviewed donor primitive materially superseded these owners.

## Explicit higher-authority non-promotions

A literal union of every peer feature would make LumiNet incoherent and less safe. The following were re-examined and remain outside target product authority: arbitrary host process termination, a second generic firewall blocker, raw fake-TCP/SNI packet injection services, the legacy obfuscated-OpenSSH fork, a multi-user Xray reseller/server-administration control plane, a general OIDC provider, a parallel GTK UI/toolchain, and an untrusted scraped public proxy corpus. These are explicit dispositions with substitute/value boundaries, not skipped directories.
