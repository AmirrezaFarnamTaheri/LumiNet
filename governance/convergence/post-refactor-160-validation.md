# Post-refactor-160 validation

## Verified repository gates

The following checks were executed successfully against the converged target after the post-160 source changes:

- source structure and canonical `.context` navigation
- repository topology and LumiCore source purity
- daemon and desktop reachability
- Android TUN ownership, binding, adapter parity, and product ownership
- host product, request-context, host-network, runtime-core, and proxy-facade ownership
- dormant-surface pruning and scanner liveness
- telemetry truth, job contracts, evasion truth, advanced capability truth, per-app capability truth, and advanced-runtime pruning
- subscription ownership/pruning and remote HTTP action audit
- second through ninth order convergence gates
- final and ultimate convergence gates
- refactor audit and post-refactor 83/97/117/137/141/160 convergence gates
- direct-client-IP trust, route truth, platform capability truth, native degraded truth, and proxy liveness
- final pruning, proxy qualification ownership, LumiCore ABI, Rust FFI source contracts, FFI runtime safety, FFI dead-surface checks, native dormant surfaces, and native verification coverage
- 5 `test_lumicore_link.py` Python tests
- legacy `validate_convergence.py` and `check_peer_convergence.py`
- repository audit: 0 errors; one warning that the repository intentionally has no local Android Gradle wrapper and CI/release provisions Gradle 9.5.0
- Go target selection: 7 targets, 0 errors
- Go declaration integrity: 1,534 parsed Go files, 0 syntax errors, 0 duplicate active declarations across linux/amd64, windows/amd64, darwin/amd64, and android/arm64

The post-160 convergence gate verifies exact denominators at the frozen source state: 19 donors, 12,285 peer file surfaces, 2,185 directories, 44 module/build records, 70,594 declarations, 410 ledger records, 9 fine peer-derived records, 584 cross-repository byte-overlap groups, and the exact target delta.

## Validation blockers and claim boundaries

These are environment/toolchain limitations, not passes:

- **Go package tests:** blocked. The sandbox provides Go 1.23.2 while `go.work` requires Go >= 1.26.0 and selects Go 1.26.5. `GOTOOLCHAIN=local go test ...` fails before package execution with that version requirement. Go source parsing/declaration integrity is verified, but the new Go unit tests are not runtime-executed here.
- **Rust/Cargo tests:** blocked because `cargo` and `rustc` are not installed in the sandbox. Repository FFI/source-contract checkers pass, but Cargo-backed runtime/link tests are not executed here.
- **Control UI TypeScript build:** blocked by absent local dependency type packages. `npm run typecheck -- --pretty false` reaches TypeScript and reports missing `vite/client` and `node` type definitions. Task-created `node_modules` was removed from the source tree; no dependency tree is shipped.
- **Android Kotlin/Gradle compile:** blocked because neither a repository Gradle wrapper nor a system Gradle executable is available. Static mobile ownership/product checks pass. The release workflow remains the owner of Gradle 9.5.0 and generated `libs/luminet.aar` provisioning.
- **Live iperf3 interoperability:** blocked because `iperf3` is not installed and no authorized external server was supplied. The code now reports the missing executable truthfully instead of synthesizing throughput.
- **Live STUN/Tor external probes:** not executed against third-party endpoints. Parser/planner/security semantics are source-checked and represented by Go tests, but those Go tests are toolchain-blocked as above.

## Mutation retry claim boundary

`foundation/config.Manager.Mutate` and the HTTP mutation adapter are statically validated and repository-gated. The implementation has explicit test sources for fresh-snapshot replay, explicit-precondition single-attempt behavior, bounded conflict exhaustion, callback failure, and HTTP adapter behavior. Those Go tests were not executed in this sandbox because of the pinned Go toolchain requirement.

## Residual risk

No unresolved repository-structure, convergence-accountability, source-syntax, ownership, or target-delta error remains in the executed gates. Remaining uncertainty is runtime/toolchain-specific and must be closed in the normal pinned CI/release environment before production release admission.
