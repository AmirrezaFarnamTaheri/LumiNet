# LumiNet Architecture Overview

This document describes the **current product architecture**. Historical experiments and porting candidates live under `docs/porting/`, `docs/audit/`, `governance/`, and `labs/`; they are not product capability.

## 1. Product hosts

```text
React/Vite control UI ─┬─> daemon HTTP/WebSocket host
                       └─> Wails desktop host ─> session discovery ─> daemon HTTP

Android VpnService ─> generated gomobile binding ─> mobilecore ─> mobilehost/TUN runtime

Daemon workflows ─> Go runtime/analysis modules ─> private C ABI ─> LumiCore Rust core
```

- `src/packages/control-ui/` is the sole authored browser UI. The checked `dist/` is a fail-closed bootstrap; CI/release builds replace it with the production bundle.
- `src/apps/desktop/` is the supported desktop host. It embeds the shared UI and discovers the local daemon through `contracts/session`; it does not own a second backend runtime.
- `src/apps/android/` is the supported Android host. `VpnEngineService` owns Android VPN lifecycle and hands the TUN descriptor to the generated Go mobile binding. `PerAppVpnPolicy` owns bounded allow/exclude application policy, while `UnderlyingNetworkTracker` is passive advisory underlay state rather than routing authority.
- `src/apps/daemon/` owns local control, orchestration, persistence, jobs, platform mutation, scanning, and network runtimes.
- `src/packages/lumicore/` owns the Rust native implementation behind the private Go C-declaration surface.

## 2. Daemon module shape

Daemon implementation is organized by dependency depth:

```text
foundation/native
      ↓
protocols/platform
      ↓
networking
      ↓
analysis/integrations
      ↓
runtime
      ↓
workflows
      ↓
adapters
      ↓
cmd
```

Higher-rank modules may depend downward; lower-rank modules must not import higher-rank modules. `scripts/checks/check_source_structure.py` enforces the rule from Go imports.

Key deep modules:

- **scanner** hides scan orchestration, probes, throttling, progress, and result handling behind a small caller interface.
- **proxy runtime** owns evasion lifecycle and temporary proxy qualification without absorbing mobile/platform/safety/trust ownership.
- **system** owns host-network mutation as a transaction: snapshot → recovery record → apply → verify → commit/rollback.
- **subscription ingestion** owns safe fetch, normalization, profile state, and daemon-owned refresh lifetime.
- **runtimecore** owns long-lived Tor/Psiphon process lifecycle separately from ephemeral proxy qualification.

## 3. Control-plane flow

### Browser/daemon

1. The daemon registers Gin routes; live registration plus `GET /api/routes` is route truth.
2. The shared UI calls the daemon through `ControlTransport` and typed decoders.
3. Authenticated HTTP/WebSocket adapters translate requests into lower-module interfaces.
4. Adapters do not own runtime state or detached lifetime.

### Desktop/Wails

1. `AppBridge.GetSessionConfig` reads the secure local session descriptor through `contracts/session` and applies explicit environment overrides.
2. The Wails UI uses that session for authenticated daemon calls.
3. If Wails session discovery fails, `ControlTransport` fails closed; it does not silently fall back to a different direct HTTP endpoint.
4. Browser-only mode may use its explicit environment/default transport configuration because no Wails session authority exists there.

## 4. Android data plane

1. `VpnEngineService` validates and applies the complete per-app policy, then establishes the Android TUN interface.
2. `UnderlyingNetworkTracker` passively reports eligible non-VPN physical underlays to the service without requesting or retaining network authority.
3. The generated gomobile adapter passes the TUN descriptor to `runtime/mobilecore`.
4. `mobilecore` owns TUN/runtime lifecycle and uses `platform/mobilehost` for Android socket protection and process callbacks.
5. Visible Android status is derived from the real service running state; the UI does not synthesize latency/evasion telemetry.

## 5. Native core seam

Go reaches LumiCore through `src/apps/daemon/internal/native/bridge/lumicore_abi.h`, the private host declaration surface. Rust owns implementation/layout truth and Cargo owns native link requirements.

Native surface changes require the Cargo/ABI/CGO verification matrix. Static reachability alone is not enough evidence to delete or privatize Rust modules, especially while the crate still builds an `rlib` in addition to native libraries.

## 6. Capability truth

A route or UI surface is not considered operational merely because a handler or historical implementation exists. Current guards require disconnected or simulated behavior to fail closed. Examples:

- `/api/metrics` returns unavailable while no production metrics pipeline exists.
- per-app routing is considered operational only when `PerAppVpnPolicy` validates and applies the complete Android `VpnService.Builder` policy; unsupported hosts do not pretend the mobile authority exists.
- retired advanced runtime simulations and historical compatibility surfaces remain outside active product source.

## 7. Verification authority

Run `make verify-repo` for repository structure, provenance, ownership, capability truth, FFI/ABI policy, and pruning gates. Stronger build/runtime proof remains:

- Go 1.26 daemon/desktop test and build matrix;
- Cargo format/Clippy/tests plus Go↔Rust ABI/CGO checks;
- frontend `npm test`, lint, typecheck/build;
- Android gomobile + Gradle build/tests;
- Graphify target-state analysis when available.


## 8. Post-refactor-180 convergence

The current daemon keeps one owner for each new peer-derived mechanism: subscription egress owns redirect/retry admission, diagnostics owns platform traceroute, provider corpus snapshots own longest-prefix attribution, WARP scanning owns temporal endpoint quality, LumiCore owns native IP declared-length parsing, and `platform/system/nat` owns bounded IPv4 fragment reassembly. Connection-list UX, cross-platform netmon, raw packet injection, external identity/admin planes, and generic checkpoint replay remain non-authoritative references until their prerequisite target ownership contracts exist.

## 9. Post-refactor-220 convergence

Three new deep target-owned seams now sit below the adapters/UI:

```text
runtime owners ──> foundation/flowregistry ───────────────┐
platform/system network monitor ──> network epochs ──────┼─> analysis/netintel ─> typed API ─> Connections
provider immutable LPM corpus ────────────────────────────┘

subscription/profile input ─> canonical ProxyConfig ─> bounded TransformConfigs
                                            └─────────> ConvertConfigs ─> local re-ingest proof ─> Compatibility Lab

persisted job intent ─> redacted reconstructibility policy ─> operator-confirmed new descendant ─> normal JobManager start
```

The architectural rules are explicit:

- a runtime must declare observable/close metadata coverage before publishing a flow;
- the flow registry observes lifecycle but never steals a runtime owner's close/state authority;
- network monitoring is passive evidence and cannot mutate host routes or retain platform networks;
- network intelligence performs no active network operation and reports partial runtime coverage and provider-corpus staleness;
- conversion/shaping is local-only and cannot fetch remote includes, execute scripts, or establish a second profile authority;
- strict format compatibility is post-export evidence, not an exporter assertion;
- interrupted jobs are never resumed in place or automatically at startup; a safe recovery is a new lineage-linked execution;
- the post-refactor-160 automatic config-mutation retry remains the only bounded CAS-intent replay mechanism for configuration authority.

### Capability and coverage truth

The authenticated capability surface is a read-only composition boundary. The capability registry remains the owner of registered availability; native ABI negotiation remains the owner of native-link truth; `flowregistry` owns participating runtime-flow coverage; `NetworkMonitor` owns passive network epochs; and the provider service owns corpus freshness. `/api/capabilities` schema v4 composes these owners without changing them, and the Capability & Coverage Center renders the result. Missing evidence never becomes availability.
