# LumiNet post-refactor-180 validation

## Claim boundary

This report validates the exact post-refactor-180 source tree after convergence of the 20 uploaded donors. A claim is **verified** only when an executable check was run successfully against the target source or an exact isolated copy of the current target file(s). A claim is **statically-validated** when source/checker evidence was inspected but the required native toolchain was unavailable. Repository-wide Go package execution is not claimed because LumiNet requires Go 1.26.0/toolchain 1.26.5 while this environment provides Go 1.23.2.

## Evidence-accountability validation

The post-refactor-180 convergence gate verifies the durable evidence graph rather than only checking that files exist:

- 20 donors.
- 6,232 outer donor file/symlink surfaces.
- 1,290 real directories.
- 125 build/module manifests.
- 36,779 normalized declaration discoveries.
- 142 nested file payloads.
- 2 symlinks, both confined to the `libcrafter` donor and with expected targets.
- 289 adoption/decision records: 20 donor roots, 245 donor/classification semantic records, and 24 fine mechanism decisions.
- Every outer surface resolves to exactly one donor-root record and one semantic/category disposition; fine mechanism records resolve to exact donor paths and SHA-256 evidence.
- Archive-admission rollups account for 6,230 regular files plus 2 symlinks and retain finite expansion bounds.
- Restricted/unclear-license donors are evidence only; the gate rejects direct-source-reuse claims for GPL/AGPL/unknown-license material.
- The standard peer-convergence inventory independently rehashed 6,202 non-`.git` surfaces with zero mismatches. The 30 additional strict surfaces are repository metadata from one donor and remain represented rather than silently excluded.

The final post-refactor-180 gate also checks that the previous post-refactor-160 automatic configuration mutation retry contract remains present: bounded intent replay, fresh authoritative snapshots, one-attempt semantics for explicit revision preconditions, and no relocation of runtime effects into the retry loop.

## Canonical repository verification

The final canonical repository verifier was executed in bounded bands to prevent the sandbox command ceiling from turning an unfinished tail into an apparent result. All executed gates were green on the final source implementation state.

### Structure, topology, language-selection, and declaration integrity

- Source structure: 6 roots, 10 bands, 34 cross-band edges, 0 errors.
- Source context: 120 required contexts, 0 errors.
- Tooling surface: 6 direct surfaces, 11 retired, 0 errors.
- Historical topology: 2,442/2,442 baseline paths accounted; 1,370 byte-identical, 604 reviewed transformations, 468 retired, 0 errors.
- Rust source purity: 248/248 sources accounted, 0 errors.
- Daemon packages: 55/55 reachable, 0 hidden islands.
- Desktop packages: 1/1 reachable.
- Android/mobile TUN ownership, binding parity, product ownership: 0 errors; 4 Android Kotlin source owners and one Android service.
- Go target selection: 7 target configurations, 0 errors.
- Go declaration integrity: 1,536 Go source files parsed by the repository checker, zero syntax errors.
- Active Go declaration duplicate scan: zero duplicate declarations on linux/amd64, windows/amd64, darwin/amd64, and android/arm64.

### Runtime and authority ownership

All of the following repository gates completed with zero errors: daemon lifecycle, request context, host-network ownership, runtime-core ownership, proxy-facade ownership, dormant-surface pruning, scanner liveness, telemetry truth, job-contract ownership, evasion truth, advanced capability truth, per-app capability truth, advanced-runtime pruning, subscription ownership, and subscription pruning.

The remote HTTP action audit reported 29 actions, 17 constructors, 3 dynamic wrappers, zero raw Python mutations, 13 mutations, 6 query-over-POST actions, 8 side-effect actions, and 2 stream transports, with zero errors.

### Historical convergence preservation

Every historical convergence gate through post-refactor-180 passed. This includes second-order through ninth-order convergence, final convergence, ultimate convergence, refactor audit, post-refactor-83/97/117/137/141/160, and the new post-refactor-180 gate. The post-refactor-160 checker is successor-frozen against the immutable pre-180 baseline instead of being weakened to accept descendant changes.

### Native/route/security tail

All route truth, platform capability truth, native degraded truth, proxy liveness/pruning/qualification, LumiCore ABI, Rust FFI refactor/safety/dead-surface, dormant native surface, and native verification-coverage gates completed with zero errors. The Python-side FFI link suite ran 5 tests successfully. The convergence validators and repository audit completed with zero errors.

The repository audit emits one inherited/documented warning: the Android Gradle wrapper is not checked into the repository; CI/release provisions Gradle 9.5.0.

## Executed focused behavior validation

Because the repository Go workspace requires a newer Go toolchain than is installed, standard-library-only packages/slices were copied from the exact current target into isolated Go 1.23 modules. Hash equality of the target files was checked when the harnesses were built; harness-only stubs are called out below. These focused suites validate the changed semantics without claiming full workspace compilation.

### IPv4 NAT reassembly — verified

Exact current target defragmentation/IP packet implementation: **8/8 tests pass**.

Validated behaviors:

1. normal fragmented datagram reassembly;
2. out-of-order final fragment before offset-zero fragment, while preserving the offset-zero header as authoritative;
3. identical duplicate overlap acceptance;
4. conflicting overlap rejection plus flow deletion;
5. non-final payload alignment rejection;
6. deterministic oldest-flow eviction at the 256-flow bound;
7. high-offset fragment admission independent of a non-zero fragment's longer IHL, followed by authoritative final assembly bounds;
8. impossible IPv4 declared-length rejection.

The second-order high-IHL test was added after adversarial review of payload-relative fragment offsets.

### Provider longest-prefix index — verified

Exact current provider package: **9/9 tests pass**.

The suite covers existing corpus/status behavior plus priority for identical prefixes, IPv6 longest-prefix behavior, and differential equivalence between the immutable index and the prior linear reference lookup. This is the acceptance oracle for the `tailscale-rs`-inspired rederivation; the Rust BART implementation itself is not copied.

### Subscription egress follow-up policy — verified

Exact current `egress.go` with canonical target `netpolicy`: **10/10 tests pass**.

The suite includes explicit egress enablement, unsafe/special-use target rejection, HTTPS/port constraints, ETag normalization, finite redirect budget, redirect-loop rejection, and cross-origin `If-None-Match` stripping. This proves that supplying a custom Go `CheckRedirect` no longer accidentally removes finite redirect protection.

### Retry-After source backoff — verified

The isolated current source-health slice passes the parent test and all seven table cases: delta-seconds, HTTP-date, past date, invalid value, negative value, 24-hour cap, and integer-overflow input. `Retry-After` is accepted only for 429/503 and can raise, but never remove or unbound, the target-owned exponential backoff.

### Traceroute path diagnostics — verified on Linux

The parser/bounds suite passes four tests covering repeated-hop loss/jitter/load-balancing, Windows-style timeout parsing, rejection of URL/path/option-shaped targets, and bounded trace options. A separate live Linux test invokes the installed `traceroute` backend against loopback and passes. The Windows `tracert` executable path was not runtime-executed in this environment; its parser behavior is covered, not the Windows process integration.

### WARP temporal-stability ranking — verified for target ranking logic

The exact current `warp_scanner.go` and target scanner tests were run in an isolated module with only the external Cloudflare handshake primitive/public-key dependency stubbed. **11 top-level tests pass plus 6 resource-limit subcases**.

The suite verifies repeated-attempt summarization, all-failure handling, loss before latency, jitter before median latency when loss ties, attempt defaults/caps, candidate uniqueness, dual-stack split, resource bounds, early-stop correctness, noise-count admission, and operator oversubscription rejection. The WARP ranking/state/bounds logic is therefore verified; actual external WARP handshake interoperability is not claimed by this isolated suite.

## Static-only validation

### Rust IPv4/IPv6 declared-length parsing

The LumiCore parser changes are statically validated and covered by source tests, but those Rust tests were not executed because `cargo`, `rustc`, and `rustfmt` are unavailable in the environment.

The code now requires:

- IPv4 declared total length to be at least IHL and no larger than received bytes;
- IPv4 payload slicing to stop at the declared total length;
- IPv6 received bytes to cover exactly the 40-byte base header plus declared payload length before exposing the payload;
- trailing bytes beyond protocol-declared length to be excluded from payload semantics.

Negative tests for truncation, impossible length, and trailing bytes are present in the target source.

## Toolchain and environment boundaries

Observed toolchain/environment at final validation:

- target Go requirement: Go 1.26.0, toolchain Go 1.26.5;
- available Go: 1.23.2;
- available Python: 3.13.5;
- available Node: 22.16.0; npm 10.9.2;
- `cargo`, `rustc`, `rustfmt`: unavailable;
- `gradle`: unavailable;
- Linux `traceroute`: 2.1.6, live loopback test executed;
- `iperf3`: unavailable.

Attempting a normal target Go package test with `GOTOOLCHAIN=local` fails before compilation because `go.work` requires Go >= 1.26.0. This is an environment/toolchain block, not recorded as a passing or failing package suite.

## Not claimed

The following are deliberately not claimed as verified:

- full Go workspace/package test execution under Go 1.26.5;
- Rust unit-test or cargo build execution;
- Android Gradle build/emulator execution;
- Windows `tracert` process execution;
- live external WARP handshake interoperability from the isolated scanner harness;
- live `iperf3` execution in this environment;
- a universal cross-runtime connection ledger/UI, daemon-wide cross-platform netmon, or generic automatic job replay, because the required authority/idempotency prerequisites do not yet exist.

## Validation conclusion

For the post-refactor-180 source changes, all available canonical repository gates are green, all Go source/declaration ownership checks are green, and the high-risk standard-library-only behavior slices execute successfully against exact current target source. The remaining unexecuted validation is explicitly attributable to unavailable/newer native toolchains or external/platform dependencies rather than silently promoted to success.
