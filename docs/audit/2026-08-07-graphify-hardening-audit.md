# LumiNet Graphify hardening audit — 2026-08-07

Revision audited: `01d7c5d` on `refactor/graphify-architecture` (plus the six preceding local hardening commits listed below).

This is an **incremental exhaustive audit** over the cleaned Graphify refactor branch. It supersedes the release-state conclusions in `2026-08-07-project-audit.md`; that older document remains useful as the original archive-recovery baseline.

## Audit contract

Mode: **Improve** — inspect the cleaned repository, make only evidence-backed low-risk changes that can be verified in the available environment, and leave blocked changes as implementation-ready findings.

Constraints observed during this pass:

- Project Go requirement: Go 1.26.x. Available locally: Go 1.23.2. The Go toolchain download is blocked by container DNS.
- Rust/Cargo: unavailable. Rust findings are static-only and no Rust source is changed.
- Android Gradle/SDK/ADB: unavailable. Kotlin compiler exists, but the Android app cannot be built or run.
- Frontend `node_modules`: unavailable; offline npm install is incomplete. Dependency-free TypeScript contract code can still be compiled and tested.
- No writable LumiNet GitHub repository is connected. Tracker-oriented refactor skills therefore cannot publish an issue from this checkout.
- No Codex CLI, Refly CLI, or skills-manager CLI is present in the execution container. No independent external-model review is claimed.

## Graph/topology baseline

This historical audit recorded Graphify 0.9.34 as the tool that produced the structural baseline below. A later reproducibility check on 2026-08-09 could not match that version to the then-public Graphify package/release sources; the current repository therefore pins public `graphifyy==0.9.26` and verifies its wheel hash in CI while preserving these counts as historical evidence. Transitive Python dependencies remain resolver-managed rather than fully lockfile-pinned.

Historical structural baseline:

| View | Code files | Nodes | Edges | Communities |
| --- | ---: | ---: | ---: | ---: |
| Full repository | 505 | 5,359 | 10,028 | 402 |
| First-party production | 355 | 3,839 | 7,031 | 309 |

The graph is a prioritization aid, not proof by itself. Generic-name inferred edges are treated as prompts; findings below require implementation traces, tests, or direct contract mismatches.

## Coverage ledger

| Surface | Disposition | Evidence / boundary |
| --- | --- | --- |
| Repository source boundary | **Exercised** | `scripts/repo_audit.py` returns 0 errors; orphan `client/src` prototype archived and forbidden from reappearing live. |
| Go scheduler / limiter concurrency | **Exercised** | Three shutdown/lifecycle bugs reproduced and fixed with isolated Go 1.23 race-detector tests. |
| Go jobs lifecycle | **Inspected, blocked** | State/scheduler traces inspected; package compilation blocked by required Go 1.26 toolchain and uncached dependencies. |
| Go API/WebSocket lifecycle | **Inspected, blocked** | Hub subscription + HTTP shutdown trace inspected; API package cannot be compiled locally. |
| Desktop TypeScript transport contracts | **Exercised (pure contract seam)** | New dependency-free decoder harness compiles `contracts.ts`; 7 checks pass; harness was falsified with a known-bad clamp. |
| Desktop React UI | **Inspected, blocked** | Static a11y/state/effect review performed; full lint/build/browser verification blocked by missing npm dependencies. |
| Android/Kotlin | **Inspected, blocked** | Manifest ↔ launcher reachability traced. No Gradle wrapper/SDK/ADB, so no app build or emulator claim. |
| Rust core / FFI | **Inspected, blocked** | Panic, lock, FFI, and stub reachability reviewed statically. No `cargo`/`rustc`; no Rust edit accepted. |
| CI / supply chain | **Mapped** | Workflow action inputs are SHA-pinned in the cleaned branch; the earlier floating-tag warning is historical. |
| Observability | **Inspected** | Prometheus endpoint, Go system metrics, WebSocket event flow, Rust tracing, and desktop telemetry consumers traced. |
| Performance | **Mapped, no optimization authorized by evidence** | No repeatable latency/CPU/profile baseline is available in this environment; no speculative optimization performed. |
| Chaos/resilience | **Planned only** | No production-like runtime + abort/observability setup is available; destructive fault injection is not run. |

## Verified changes in this hardening wave

### H-01 — Archived an unowned React subtree

Commit `1d056e1` moves the four files formerly under `client/src` to `docs/porting/archive/legacy-client-ui/` without content changes. The `client` module had no frontend package manifest, build entry, or live imports for those files. SHA-256 equality was checked before/after the move.

Commit `da19fd4` adds a repository-audit invariant that rejects any live `client/src`. The new check was falsified: creating that path made the audit fail; removing it restored the clean result.

### H-02 — Limiter shutdown no longer strands waiters

Commit `2b13ce0` fixes `server/internal/relay/throttle.go`. Before the change, a queued `Acquire` could remain blocked forever after `Stop()`. The stopped limiter now becomes pass-through and releases queued requests. The reproducer and regression tests passed under `go test -race` in a standard-library-compatible isolated harness.

### H-03 — Cron runner lifecycle is restart-safe

Commit `498c56f` fixes double-start ownership in `server/internal/scheduler/runner.go`. A second `Start` could replace the only cancellation function and make `Stop` wait on an earlier goroutine set it could no longer cancel. Concurrent starts are now rejected, stop is idempotent, and start-after-stop remains supported. Race-detector tests cover both contracts.

### H-04 — Resource scheduler has a real shutdown contract

Commit `015e9da` hardens `server/internal/scheduler/scheduler.go`: stop is idempotent, submissions after stop fail, active work is awaited, and a budget-waiting job cannot be admitted after cancellation. The four lifecycle cases passed 20 repeated race-detector runs in the isolated harness.

### H-05 — Desktop wire decoding has an executable test seam

Commit `01d7c5d` adds `desktop/frontend/scripts/test-contracts.mjs` and package scripts without adding dependencies. It compiles only `src/api/contracts.ts` and checks seven server-wire conversions. The harness was deliberately broken by replacing percent clamping with identity; it failed for the intended assertion, then passed again after restoration.

## Open finding ledger

### F-01 — P1 / Statically validated — failed job submission leaves false `running` state

**Invariant:** a job must not be externally persisted or announced as running until the scheduler has accepted ownership of its execution.

`JobManager.StartJob` sets `Status=running`, sets `StartedAt`, persists the job, and publishes `status_change=running` before calling `m.sched.Submit`. If `Submit` returns an error (scheduler stopped, queue full, or future admission error), the method cancels its local context and returns while the job remains persisted and observable as running.

Evidence: `server/internal/jobs/manager.go:299-373`.

Impact: state corruption visible through list/get APIs, restart hydration, and WebSocket clients. A queue-admission failure can create a permanently misleading running job.

Required fix: define scheduler acceptance as the transition seam. Either enqueue while the job is still queued and transition after successful acceptance, or implement an explicit rollback transition that is atomic with respect to concurrent cancel/start calls. Add tests for scheduler-stop and queue-full rejection before choosing between those shapes.

Blocked proof: jobs package cannot be built with the available Go 1.23 toolchain/dependency cache.

### F-02 — P1 / Statically validated — daemon background lifetimes have no single owner

**Invariant:** every process-owned goroutine/subscription must be cancelled and awaited by the same daemon lifecycle that owns HTTP shutdown.

Current live paths violate that in several places:

- `NewJobManager` creates a resource scheduler and starts it on `context.Background()` (`manager.go:146-173`) with no manager close method.
- `serve.go` already owns daemon `ctx`, but constructs JobManager without it and starts the cron runner with a separate `context.Background()` (`serve.go:90-131`).
- `NewServer` starts `Hub.Run` and a global broadcaster subscription (`router.go:45-60`; `websocket.go:54-135`). `Broadcaster.SubscribeAll` requires caller unsubscription, but `Server.Shutdown` only stops HTTP.
- `RateLimitMiddleware` starts a ticker sweeper with no stop path (`middleware.go:100-130`).

Impact: leaked subscriptions/goroutines across server recreation/tests, non-coordinated scheduler shutdown, and work surviving beyond the daemon cancellation point.

Deep-module direction: introduce one daemon-owned lifecycle interface rather than adding unrelated stop methods at every call site. The daemon should pass a caller-owned context into long-lived modules; modules should expose only bounded close/await behavior where caller cancellation is insufficient.

### F-03 — P1 / Statically validated — Android launcher reports connection state it does not control

**Invariant:** user-visible VPN connection state must be derived from the actual VPN capability, not local presentation state.

`LumiNetActivity` stores `isConnected` in `remember` and toggles it on button click (`LumiNetActivity.kt:45-76`). It does not call `VpnService.prepare`, start a foreground VPN service, or observe a service/session state. Meanwhile the manifest declares four VPN-capable services (`AndroidManifest.xml:22-60`).

Impact: the launcher can display `CONNECTED` while no VPN service is running. This is a product correctness issue, not just missing architecture.

Decision required before implementation: name the canonical Android VPN engine the launcher owns. Do not wire the button to an arbitrary one of four services. After that decision, the Android UI should be a stateless renderer over a lifecycle-aware state holder, with service/platform mechanics behind a small semantic interface.

Blocked proof: Gradle wrapper, Android SDK and ADB/emulator are unavailable.

### F-04 — P2 / Statically validated — desktop telemetry consumes event types the server never emits

**Invariant:** every UI telemetry state must have an implemented authoritative producer.

`TelemetryService` updates RX/TX/latency only for `METRICS_UPDATE` and diagnostic runbook state only for `DIAGNOSTIC_LOG` (`TelemetryService.ts:79-104`). Repository search finds no Go producer for either event type. The server does emit `evasion_log`, which the decoder intentionally normalizes to `EVASION_LOG`.

The server already exposes authoritative cumulative traffic through `SystemStatusResponse.upload_bytes/download_bytes` (`handlers_system_status.go:77-97`) and `/api/system/traffic`, so the missing UI signal should reuse that truth instead of inventing an independent counter.

Impact: dashboard RX/TX/latency values can remain defaults while the UI presents them as live metrics.

Decision: prefer a small client-side traffic sampler over a new WebSocket event unless a push-based latency requirement is demonstrated. Compute rates from cumulative byte deltas with monotonic timestamps; define reset/reconnect behavior explicitly. Latency needs a separate authoritative measurement rather than being fabricated from traffic polling.

Proof available now: pure decoder contract tests. Full React build/runtime proof is blocked by missing dependencies.

### F-05 — P2 / Reviewed — Rust FFI runtime initialization can terminate the host

**Invariant:** recoverable Rust initialization failure must not unwind through a C/JNI/Swift ABI boundary.

`lumicore_init` is an unguarded `extern "C"` export and force-initializes `TOKIO_RT`; the runtime builder ends in `.expect("failed to build lumicore tokio runtime")` (`core/src/lib.rs:116-129`; `core/src/runtime.rs:5-15`). Other mobile FFI entry points mostly use `catch_unwind` wrappers, making this unguarded initializer an inconsistent reliability seam.

Impact: runtime-construction panic can terminate the host process instead of returning an initialization error.

Required Rust plan: replace implicit force-init with a fallible initialization result that can be represented across the ABI, then make async/streaming exports depend on that initialized state without panicking. Preserve ABI compatibility or version the contract deliberately.

Blocked proof: no `cargo`, `rustc`, `rustfmt`, or target toolchain.

### F-06 — P2 / Reviewed — mobile FFI session registries fail closed forever after lock poisoning

Android `slot_map` and iOS `session_map` use `Mutex::lock().unwrap()` inside outer `catch_unwind` guards (`android_jni.rs:267-302`; `ios_ffi.rs:301-330`). Catching the first panic prevents it crossing the ABI, but if that panic occurred while the mutex was held, the mutex remains poisoned and every later start/stop unwrap panics again, yielding default failure forever.

Direction: recover the registry guard with `unwrap_or_else(|e| e.into_inner())` only after confirming registry invariants survive unwind, or replace poisoning-sensitive state with a design where a failed session cannot corrupt the whole registry. This must be decided and tested with Cargo; no speculative Rust edit is made here.

### F-07 — P3 / Verified dormant — packed Rust scan interface returns mock success

`core/src/ffi/binary_scan.rs` marks every target alive with fixed 1500 µs latency. The Go bridge `server/internal/bridge/binary_scan.go` exposes `ExecScan`, but repository search finds no caller outside that bridge module.

Action: keep it out of production routing until implemented. Prefer removing the dormant export/bridge in a dedicated compatibility-reviewed change if no external ABI consumer exists. Do not count it as a live scanner capability.

### F-08 — P3 / Verified dormant — Android helper scopes are non-restartable

`ConnectionMonitor` and `InvizibleDaemon` own coroutine scopes that are permanently cancelled by their stop methods while public start/restart methods remain available. Launching on the cancelled scope silently does no work. Repository search finds no live callers or manifest ownership for these helpers.

Action: do not repair dormant lifecycle code yet. First decide whether it belongs to the canonical Android engine. If promoted, prefer caller-owned structured concurrency or create a fresh owned scope per explicit start/stop lifecycle.

## Deepening opportunities

1. **Daemon runtime lifecycle module — Strong.** Hide scheduler, Hub subscription, rate-limit sweeper, and other process-owned goroutine cleanup behind one small daemon lifecycle seam. This increases locality: startup/shutdown policy stops leaking into constructors and middleware factories.
2. **Job execution admission module — Strong.** Make queue acceptance + lifecycle transition one operation from the caller's perspective. Tests should exercise queued → accepted/running or queued → rejected, never internal scheduler calls.
3. **Desktop control transport module — Worth exploring.** Keep wire decoding + cumulative traffic sampling behind a small transport interface so React screens consume semantic telemetry state, not event-type trivia.
4. **Android VPN platform owner — Strong but blocked on product choice.** Pick one canonical engine, expose semantic `connect/disconnect/state`, keep `VpnService`, intents and permissions inside the Android adapter.
5. **Rust FFI runtime/session adapter — Strong but toolchain-blocked.** Keep fallible runtime init and session-registry recovery behind an ABI-safe interface; eliminate panic/poison behavior from host-visible contracts.

## Performance and chaos disposition

No performance refactor is accepted in this pass because no comparable benchmark/profile exists. Graph centrality and line counts identify complexity, not runtime bottlenecks.

No chaos experiment is run because there is no production-like environment with live observability, abort conditions, or rollback controls. The first future resilience experiment should be a development-only daemon shutdown test: create active jobs + WebSocket subscriber, cancel daemon context, and assert HTTP, schedulers, subscriptions, and job goroutines all reach zero within a bounded deadline.

## Completion boundary

This audit does **not** claim release readiness. The code changes made here are verified at the strongest locally available seams. Remaining P1/P2 findings are blocked by either an unavailable authoritative toolchain or an explicit product decision, and are transferred to `docs/plans/2026-08-07-runtime-hardening-plan.md`.
