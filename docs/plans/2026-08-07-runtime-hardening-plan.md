# Runtime hardening plan — 2026-08-07

## Objective

Finish the Graphify-led architecture hardening by making runtime ownership and capability truth explicit without changing public behavior accidentally. The target is not fewer files; it is deeper modules: small interfaces that hide lifecycle, queue-admission, transport, and platform mechanics while leaving callers with fewer invariants to remember.

Source audit: `docs/audit/2026-08-07-graphify-hardening-audit.md`.

## Architecture decisions

- **Caller owns long-lived cancellation.** Daemon/application lifecycle context flows downward; constructors do not hide background loops on `context.Background()`.
- **Admission precedes running state.** A job is not persisted/broadcast as running until its scheduler has accepted it.
- **One source of telemetry truth.** Reuse server traffic counters; do not duplicate counters merely to satisfy a WebSocket event name.
- **Android UI cannot choose an engine implicitly.** Canonical VPN-engine ownership is a product decision and blocks implementation.
- **FFI never relies on panic for recoverable initialization.** Rust runtime/session failures become explicit ABI outcomes.
- **No speculative performance work.** Every optimization needs a comparable baseline and post-change measurement.

## Touchpoints

Likely read/change surfaces by phase:

- `server/internal/jobs/manager.go`, scheduler package, broadcaster tests
- `server/internal/api/router.go`, `websocket.go`, `middleware.go`, lifecycle-focused API tests
- `server/cmd/serve.go`
- `desktop/frontend/src/api/*`, `src/store/systemStore.ts`, dashboard consumers, `scripts/test-contracts.mjs`
- `mobile/android/app/src/main/**` after canonical engine decision
- `core/src/lib.rs`, `core/src/runtime.rs`, `core/src/ffi/{android_jni,ios_ffi}.rs` after Rust toolchain is available

## Public contracts

Must remain stable unless a phase explicitly versions them:

- HTTP route set and existing response JSON names.
- WebSocket authentication and existing event envelope.
- Job status values (`queued`, `running`, `completed`, `failed`, `cancelled`) and persistence format.
- Desktop telemetry semantic state exposed to screens.
- Android user-visible connection state must become truthful; exact engine selection is unresolved.
- Existing Rust C/JNI/Swift ABI symbols; if `lumicore_init` return type changes, version/add a new symbol rather than silently breaking callers.

## Blast radius

| Phase | Risk | Expected files | Why |
| --- | --- | ---: | --- |
| 1. Job admission correctness | High | 2-4 | State-machine + persistence + concurrency |
| 2. Daemon lifecycle owner | High | 4-7 | Multiple goroutine/subscription owners |
| 3. Desktop telemetry truth | Medium | 3-5 | UI state + transport timing semantics |
| 4. Android VPN owner | High | 4-8 | Platform permission/service lifecycle; product decision |
| 5. Rust FFI hardening | High | 3-6 | ABI + panic + runtime/session ownership |
| 6. Target-state Graphify / residual audit | Low | reports only | Verification and architecture comparison |

## Phase 1 — Make scheduler acceptance the JobManager transition seam

### Commit 1.1 — Add scheduler-rejection characterization tests

- Make JobManager testable against a scheduler/admission adapter with the smallest interface needed by JobManager (prefer `Submit` plus lifecycle only if tests require it).
- Add a fake that deterministically rejects submission.
- RED tests:
  - queued job remains queued after rejected submission;
  - no `running` event is published on rejection;
  - persisted status remains queued (or explicit failed if that policy is chosen and documented);
  - cancel/start concurrency has one legal terminal/accepted path.

**Gate:** package tests compile and fail for the current behavior for the intended assertions.

### Commit 1.2 — Move running transition after accepted ownership

- Perform the smallest state-machine change that makes admission and status consistent.
- Avoid holding JobManager locks across scheduler calls if the scheduler can block.
- Define exactly when `StartedAt` is assigned.

**Gate:** focused jobs tests + race detector pass.

### Commit 1.3 — Persistence/WebSocket regression matrix

- Assert persisted state and emitted events match in success, stopped-scheduler, queue-full, cancellation-before-run, and normal completion cases.

**Gate:** focused tests + repository route/contract tests.

## Phase 2 — Deepen daemon lifecycle ownership

### Commit 2.1 — Make Hub lifecycle explicit and unsubscribe correctly

- Give Hub an explicit caller-owned context or bounded `Close`/`Wait` interface.
- Store the global job subscription and call `Broadcaster.UnsubscribeAll` exactly once.
- Close/evict clients without sending on closed channels.

**RED gate:** construct/start/close Hub; prove its Run loop and forwarding goroutine terminate and global subscription count returns to baseline.

### Commit 2.2 — Make rate-limit sweeping caller-owned

- Replace the hidden immortal ticker with a limiter module whose cleanup loop is context-owned, or eliminate background sweeping if a bounded on-request cleanup strategy is simpler.
- Middleware callers should learn no cleanup internals.

**Gate:** fake-clock or short-interval test proves stale bucket cleanup and stop without goroutine leak.

### Commit 2.3 — Bind JobManager scheduler to daemon lifetime

- `NewJobManager` must not start long-lived work on `context.Background()` as an unobservable constructor side effect.
- Prefer explicit `Start(ctx)`/`Close` only if the manager truly owns background work; otherwise inject/start the scheduler from the daemon composition root.
- Ensure stdio mode owns the same cleanup contract.

**Gate:** active scheduled job + daemon cancellation stops admission and waits boundedly.

### Commit 2.4 — Use daemon context for cron Runner

- Start cron runner with the existing daemon `ctx` instead of a new background context.
- Keep `runner.Stop()` as an idempotent join/cleanup gate.

**Gate:** daemon cancellation test; no change to schedule semantics.

### Commit 2.5 — Server shutdown integration

- `Server.Shutdown` coordinates HTTP + Hub/limiter cleanup exactly once.
- Keep timeout semantics explicit: timeout bounds waiting; it does not silently abandon ownership.

**Gate:** server lifecycle integration test repeated under `-race`.

## Phase 3 — Make desktop telemetry truthful

### Commit 3.1 — Characterize traffic JSON contract

- Extend the existing dependency-free contract harness for `upload_bytes` / `download_bytes`.
- Define cumulative-counter reset behavior and numeric bounds.

**Gate:** known-bad decoder specimen fails; restored decoder passes.

### Commit 3.2 — Introduce cumulative traffic sampler

- Add one transport-owned sampler that polls the existing traffic/status endpoint.
- Calculate RX/TX rates from `(delta bytes)/(delta monotonic time)`.
- On reconnect/reset/counter decrease, reset baseline instead of emitting a negative spike.
- Do not fabricate latency; leave it unknown until an authoritative latency source exists.

**Gate:** deterministic sampler tests with fake time and counter sequences.

### Commit 3.3 — Wire semantic metrics to store/screens

- React screens consume semantic metrics; they do not know whether data came from polling or WebSocket.
- Preserve accessibility/reduced-motion behavior.

**Gate:** full frontend `npm run check` and browser smoke test when dependencies are available.

## Phase 4 — Android VPN capability owner (blocked decision)

### Decision gate 4.0 — Choose canonical engine

Required answer: which manifest-declared VPN implementation is the launcher's default engine, and whether users can select alternatives. Until this is resolved, do not make the button start an arbitrary service.

### Commit 4.1 — Model connection state in a state holder

- Use explicit `Disconnected / Preparing / Connecting / Connected / Error` state.
- UI is stateless and renders this state.
- One-shot permission/service-launch effects are lifecycle-aware.

### Commit 4.2 — Add small semantic VPN interface

- Common/UI caller sees `connect`, `disconnect`, and state—not Android intents/service class names.
- Platform implementation owns `VpnService.prepare`, foreground service lifecycle, and service binding/observation.

### Commit 4.3 — Remove false local state and hard-coded telemetry

- Remove `remember { mutableStateOf(false) }` as connection truth.
- Replace fake `Latency: 24 ms` / `Evasion: uTLS Active` with observed values or clearly unavailable state.

**Gate:** Gradle unit tests + instrumented/emulator connect/disconnect/permission-denied flow.

## Phase 5 — Rust FFI runtime/session hardening (toolchain gate)

### Commit 5.1 — Add panic-boundary tests

- Require `cargo test`, `cargo check`, `cargo fmt --check` before any production edit.
- Add tests/probes demonstrating runtime-init failure representation and poisoned-session-lock recovery behavior.

### Commit 5.2 — Make runtime initialization fallible across ABI

- Preserve current `lumicore_init` ABI or add a versioned fallible initializer; do not silently change a public C symbol's return type.
- Async/stream APIs must return an explicit not-initialized/init-failed result instead of forcing Lazy runtime panic.

### Commit 5.3 — Make session registry poisoning policy explicit

- Recover poison only if session-map invariants are still valid; otherwise rebuild/mark registry failed with an explicit host-visible error.
- No `lock().unwrap()` in host-facing session lifecycle paths.

### Commit 5.4 — Audit remaining unguarded exports

- Classify every `extern "C"`/`extern "system"` export as infallible-by-contract or panic-contained.
- Keep unsafe blocks minimal and documented; do not do a Rust-2024 edition migration as part of this fix.

**Gate:** native Rust tests + FFI smoke tests + target-specific Android/iOS build where applicable.

## Phase 6 — Target-state topology and residual audit

- Run Graphify on this exact branch, not public main.
- Compare the routing, API, JobManager, daemon lifecycle, desktop transport, Android owner, and FFI communities to the recorded baseline.
- Do not optimize for raw node count; inspect extracted cross-community edges and caller interface surface.
- Re-run `scripts/repo_audit.py`, all authoritative language checks, and release workflow checks.

## Verification evidence

| Gate / Scenario | Strategy | Proves SPEC criterion |
| --- | --- | --- |
| `python3 scripts/repo_audit.py` | Fully automated | Source boundary and repository invariants remain clean |
| jobs scheduler-rejection tests under `go test -race` | Fully automated | Rejected admission cannot create false running state |
| daemon start/cancel/await integration test | Fully automated | Background work has one lifecycle owner |
| frontend decoder + sampler deterministic tests | Fully automated | UI telemetry derives from authoritative counters with correct reset/time semantics |
| `npm run check` + browser smoke | Hybrid | React integration remains buildable and user-visible metrics update correctly |
| Android Gradle unit + emulator flow | Hybrid | UI state matches actual VPN lifecycle and permission outcomes |
| `cargo fmt --check && cargo check && cargo test` | Fully automated | Rust changes compile, format, and preserve behavior |
| target-platform FFI smoke | Hybrid | Rust failures do not escape host ABI and sessions recover/stop correctly |
| post-refactor Graphify diff | Agent probe | Deepening reduced leaked ownership/invariants without introducing cycles |

## Test infra improvement notes

- Added the dependency-free desktop contract harness in `01d7c5d`; retain it even after a full frontend test framework is available because it is a fast wire-contract gate.
- Jobs currently binds directly to concrete store/scheduler types, making rejection/state-machine tests expensive. Introduce the narrowest internal test seam needed; do not generalize it into a framework.
- Android has zero tests in the cleaned module and no wrapper. Generate the pinned wrapper and establish one state-holder test before feature work.
- Rust has substantial inline tests but no executable toolchain in this environment; no Rust completion claim is valid here.

## Pre-mortem gates

Assume the hardening program failed after implementation:

1. **Shutdown hung with active jobs.** Cause: ownership was split across HTTP, scheduler, Hub, and middleware cleanup. Prevention: one daemon cancellation test must start all live background owners and prove bounded termination before merge.
2. **Jobs were lost or shown in the wrong state.** Cause: admission/state transition ordering changed under concurrency. Prevention: scheduler-rejection + cancel/start race tests under `-race`; no status event before accepted ownership.
3. **Dashboard showed believable but wrong rates.** Cause: sampler mixed cumulative totals, reconnects, and wall-clock time. Prevention: fake monotonic-time tests for counter reset/decrease, reconnect, zero interval, and large delta.
4. **Android button started the wrong VPN implementation.** Cause: agent guessed among four manifest services. Prevention: Decision gate 4.0 is a hard stop; no implementation before canonical owner is recorded.
5. **Rust FFI refactor crashed native hosts.** Cause: panic/ABI behavior changed without target compile. Prevention: Cargo + target build is a hard gate; Rust phase cannot be completed from static review alone.

## Out of scope

- Broad proxy-package reorganization without a concrete seam and tests.
- Java-to-Kotlin migration merely for language consistency.
- TypeScript package/dependency-cruiser restructuring for this single small frontend package.
- Performance tuning without benchmarks/profiles.
- Production chaos injection.
- Rust edition migration.
- Repairing dormant Android helpers before their capability is promoted into the live product.

## Resume and execution handoff

1. **Selected plan:** `docs/plans/2026-08-07-runtime-hardening-plan.md`
2. **Last completed step:** audit + safe locally verifiable hardening through commit `01d7c5d`.
3. **Validate contract status:** pending for remaining phases; current audit findings are source-backed but blocked phases need their authoritative toolchains.
4. **Supporting context:** `docs/audit/graphify-first-party-analysis.md`, `docs/audit/2026-08-07-graphify-hardening-audit.md`, `.graphifyignore`.
5. **Next step:** when Go 1.26 dependencies are available, start Phase 1 with scheduler-rejection characterization tests. Do not begin Android Phase 4 before the engine-owner decision or Rust Phase 5 before Cargo is available.

## Validate Contract

(placeholder — write the execution validation contract after the required toolchains are available and before each blocked phase is executed.)
