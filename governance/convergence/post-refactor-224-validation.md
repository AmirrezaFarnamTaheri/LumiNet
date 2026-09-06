# Post-refactor-224 validation

## Result

Post-refactor-224 source convergence is **verified within the claim boundaries below**. Donor evidence, exact predecessor delta, source/topology ownership, historical convergence, live route/ABI/FFI checks, focused executable capability suites, UI characterization, and repository audit all pass on the final pre-release source state.

The release is a **source release**, not a claim that every native binary was rebuilt in this sandbox. Repository modules require Go 1.26.0/1.26.5, while the available local Go toolchain is 1.23.2 and outbound toolchain download is blocked. Rust `cargo`, local `gradle`, `govulncheck`, and Graphify are unavailable. Those environment limits are recorded rather than converted into false passes.

## Evidence closure

- Frozen predecessor baseline: **2,946 paths**.
- Exact 223 -> 224 delta: generated from the frozen baseline and recomputed by the 224 checker; the final count is regenerated after this validation file is written.
- Donor archives: **15/15** verified for CRC, path safety, duplicates/case collisions, symlink confinement, and archive-to-extracted byte equality.
- Donor surfaces: **913/913** = 911 regular files + 2 confined symlinks.
- Donor directories/subdirectories: **153**.
- Definition-level donor symbols: **2,256**.
- Semantic records: **72**.
- Focused surfaces: **773**; supporting/package/admin/documentation/fixture/media leaves: **140**.
- High-signal implementation/test/script/deployment/UI leaves linked only to donor-base records: **0**.
- Non-reference semantic records with unique acceptance-evidence nodes: **42/42**.
- Semantic validation status: **71 verified**, **1 statically-validated** (`KCPGO003`, opt-in AES-GCM against exact pinned kcp-go v5.6.72 API).
- Evidence regeneration was run twice from the original donor ZIPs; archive, surface, directory, symbol, ledger, summary, predecessor-baseline, and target-delta outputs were byte-stable across runs.

## Focused executable validation

The 224 packages that do not require the repository-wide Go 1.26 toolchain were copied directly from the live source into isolated local modules and run uncached with Go 1.23.2:

- `kcppolicy`: `go test -count=1 ./...` — PASS.
- endpoint/mesh/L7/traffic/routing diagnostics: `go test -count=1 ./...` — PASS.
- DoH resolver-pool planner: `go test -count=1 ./...` — PASS.
- integration presets: `go test -count=1 ./...` — PASS.
- adaptive relay state/polling: `go test -count=1 ./...` — PASS.
- complete proxyconfig parser package + 224 regression corpus: `go test -count=1 ./...` — PASS.

These runs exercise bounded FEC/explicit overrides, endpoint health/circuit/capacity and quality-band ordering, stale mesh evidence, offline L7 admission, declarative traffic profiles, routing provenance/presets, DoH admission/circuit/fallback planning, Quad9 preset separation, relay idle-vs-error retry state, ambiguous-authority rejection, seven credential-free protocol shapes, and KCP share-link round trips.

## Control UI validation

`npm test` runs the dependency-free historical/product characterization chain and passes **220 checks**. The preserved post-refactor-223 UI suite adds **9 checks**, for **229 total passing characterization checks** across the current Control UI evidence chain. Post-refactor-224 contributes 30 checks covering endpoint strategies, authenticated planning routes, read-only operator copy, mutation/WebSocket reliability contracts, version-skew defaults, and Dashboard truth surfaces.

Additionally:

- `tsc -p tsconfig.json --noEmit --pretty false` using available global TypeScript 5.8.3 — PASS with exit code 0.
- 224-changed Go files checked with `gofmt -l` — 34 files checked, 0 unformatted.

## Canonical repository verification

Every command in the `verify-repo` Makefile recipe was run in its declared order, split into bounded execution bands so a host wall-clock limit could not hide the terminal status. All assertions pass after removing only task-created Python bytecode caches.

Representative final results include:

- source structure/context/tooling: PASS (`source-context required=126 errors=0`, tooling errors=0).
- topology: PASS (`baseline_accounted=2442/2442`, transformed=609, retired=470, errors=0).
- Go declaration integrity: PASS (`parsed_files=1607`, zero syntax errors and zero duplicate declarations on linux/amd64, windows/amd64, darwin/amd64, android/arm64).
- subscription ownership/pruning, runtime/core/proxy/telemetry/job/evasion truth: PASS.
- historical convergence: PASS through post-refactor-220, 222, and frozen post-refactor-223.
- post-refactor-223: PASS with its frozen **10,331 surfaces / 51,441 symbols / 56 semantic records**.
- post-refactor-224: PASS with **15 archives / 913 surfaces / 153 directories / 2,256 symbols / 72 semantic records** plus exact predecessor-delta verification.
- route/platform/native-degraded/proxy qualification/liveness/final pruning: PASS.
- LumiCore ABI, Rust FFI refactor, FFI runtime safety/dead-surface, native dormant-surface and verification-coverage checks: PASS.
- `test_lumicore_link.py`: 5 tests PASS.
- convergence schema/peer convergence: PASS.
- repository audit: PASS with one environment warning only: no local Android Gradle wrapper; CI/release metadata provisions Gradle 9.5.0.

## Toolchain and release claim boundary

- Repository `.go-version`: **1.26.5**; Go module declarations require **go 1.26.0**.
- Available local Go: **1.23.2** with `GOTOOLCHAIN=local`.
- Attempting the repository tool module under the local toolchain fails before compilation with `go.mod requires go >= 1.26.0`.
- Automatic Go 1.26.5 download is blocked by sandbox DNS/network access to `proxy.golang.org`.
- `cargo`: unavailable.
- local `gradle`: unavailable.
- `govulncheck`: unavailable.
- Graphify: unavailable.
- Node: 22.16.0; npm: 10.9.2; global TypeScript: 5.8.3.

Therefore this evidence supports a verified **source-level successor release** and the focused executable behaviors above. It does not claim a full Rust/Go/Android/native binary rebuild, dependency vulnerability audit, or packaged application build in this environment.

## Known inherited residue

`scripts/vendor/github.com/santhosh-tekuri/jsonschema/v6/.swp` is present in the frozen 223 predecessor with the identical SHA-256 `5af4a53d9bfe0e29bcacc1dbce31977b955f807fefb82fb846df4aea2683354f`. It is inherited byte-identical vendor content, not task-created residue, and is preserved to avoid silently rewriting the predecessor payload during this convergence wave.

## Release gate

After this document is included, the target delta must be regenerated, post-refactor-224 verification rerun, task-created caches rescanned, source bytes frozen, and the deterministic archive independently extracted and compared path/type/hash-for-hash against the frozen source manifest. Only that same verified archive may receive the final release receipt and checksums.
