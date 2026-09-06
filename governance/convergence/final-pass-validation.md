# LumiNet final convergence validation report
## Claim boundary
The local environment provides Go 1.23.2 while the repository declares Go 1.26.0/toolchain 1.26.5, and external toolchain/module download is unavailable. Rust/Cargo are unavailable. Therefore this report does **not** claim a dependency-bound `go test ./...`, Rust build, Android native build, or cross-platform packaged-runtime equivalence. Changed Go contracts are validated through exact isolated harnesses copied from the final source, repository ownership/static gates, and inherited ninth-order regression harnesses whose source bytes were compared with the final target before execution.
## Focused final-pass behavioral evidence
- Provider-scoped remote mutation coordinator: **100 full package repetitions under `go test -race`**, plus `go vet` — pass. Covers shared cooldown, provider isolation, in-flight bound, active-scope capacity fail-closed behavior, cancellation, safety classes, reconciliation, jitter, exact Retry-After, and telemetry counters.
- Canonical config/secret authority: **100 full package repetitions under `go test -race`**, plus `go vet` — pass. Covers stale writer rejection, owned snapshots, generated refs, secret copy-on-write/rollback, failed-save revision behavior, restart generation, legacy migration, external reused generation advancement, and byte-identical self-reload no-churn.
- HTTP config CAS adapter: **100 repetitions**, plus `go vet` — pass. Includes strict ETag parsing and 412-versus-409 conflict semantics.
- Unix DNS-leak platform truth: exact isolated copy of final `platform_support.go` + `firewall_unix.go`, **100 race-enabled repetitions**, plus `go vet` — pass. Confirms non-Windows support remains false and enable fails with `ErrUnsupportedPlatformFeature`.
## Revalidated ninth-order executable slices
Before execution, the ninth-order harness copies for WARP scanner/noise, speedtest runner/metrics, entitlement evaluator, and WARP handshake were byte-compared with the current final target and matched.
- WARP scanner/noise: **100 repetitions under `-race`**, `go vet` — pass.
- Speedtest metrics: **100 repetitions under `-race`**, `go vet` — pass.
- Speedtest runner/resource bounds: **100 repetitions under `-race`**, `go vet` — pass.
- Entitlement evaluator: **100 repetitions under `-race`**, `go vet` — pass.
- WARP handshake: race-enabled compilation/test command + `go vet` — pass (package contains no direct test functions).
- Control UI contract characterization: **30 checks passed**. Isolated `Profiles.tsx` TypeScript/TSX compile — pass; harness Profiles/contracts source matched current final target.
## Repository-wide governance and architecture validation
The canonical `verify-repo` command sequence was executed in bounded groups against the final source state. Its constituent gates include source/context/tooling structure, repository topology, product/platform reachability, host-network/runtime/proxy ownership, scanner/telemetry/job/evasion/subscription truth, remote HTTP action classification, every convergence wave through final, platform/route/native truth, proxy pruning/qualification, ABI/FFI/native dormant-surface checks, LumiCore link unit tests, convergence validation, peer convergence, and repository audit. Exact final outputs are captured in the evidence bundle.
The prior monolithic run reached the final repo audit with all preceding gates green; the sole error was the verification process creating `scripts/checks/__pycache__`. The Makefile now exports `PYTHONDONTWRITEBYTECODE=1`, the residue was removed, and repo audit subsequently returns errors=0 with only the existing Android Gradle-wrapper environment warning.
## Evidence statuses
- Final all-43 strict convergence checker: **verified** — `donors=43 members=9556 directories=1516 surfaces=8040 symlinks=37 modules=523 symbols=17724 historical_semantics=60 new_semantics=9 records=592 supersession=13 repairs=15 high_level_planes=18 baseline=2546 changes=37 errors=0`. It checks archive safety, hashes, ledger dependencies, target/test anchors, historical revalidation, higher-level plane evidence, full-donor supersession coverage, exact delta, and live invariants.
- Repository topology: **verified** — `baseline_accounted=2442/2442 byte_identical=1385 transformed=593 retired=464 errors=0`.
- Remote HTTP action audit: **verified** — `actions=29 constructors=17 dynamic_wrappers=3 python_raw_mutations=0 mutation=13 query-over-post=6 side-effect=8 stream-transport=2 errors=0`.
- Native verification coverage: **verified** — `checks=22 errors=0`; ABI/FFI/dead-surface/native-dormant checks all report errors=0.
- Peer convergence legacy/global gate: **verified** — `unresolved_high_signal=0 ... errors=0`.
- Repository audit: **verified** — `errors=0 warnings=1`; the sole warning is the declared missing local Android Gradle wrapper.
- Dependency-bound whole-workspace Go/Rust/native builds: `unverified` due to unavailable declared toolchains/dependencies, not inferred from focused tests.
## Known environment limitation
- Android Gradle wrapper is absent locally; repository audit reports this as a warning and CI/release pins Gradle 9.5.0.
- Go 1.26.x declared toolchain cannot be fetched in this offline environment; local Go 1.23.2 is used only for dependency-isolated harnesses.
- Cargo/Rust unavailable; final pass introduces no Rust source changes.
