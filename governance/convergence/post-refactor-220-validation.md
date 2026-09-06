# Post-refactor-220 validation

## Claim boundary

Post-refactor-220 is a source-level implementation and clean-source release-validation wave over the 40-project convergence universe (LumiNet + 39 uploaded donor archives). The historical donor inventories are not re-labeled as runtime tests: post-refactor-160 accounts for 12,285 donor surfaces and post-refactor-180 for 6,232, for 18,517 cross-wave donor file/symlink surfaces.

Statuses in this report mean exactly:

- **verified**: the named command/test executed successfully against the stated source or an exact-source isolated standard-library harness;
- **statically-validated**: syntax/source/ownership characterization executed, but the full production toolchain/runtime did not;
- **reviewed**: manual mechanism/evidence review without an executable claim.

## Executed focused evidence

| Capability | Evidence | Result | Status |
|---|---|---:|---|
| Canonical flow registry | exact current `flowregistry/registry.go` + tests copied into Go 1.23 stdlib isolate | 9 top-level tests pass | verified |
| Passive daemon network epochs | exact current `network_monitor.go` + tests in stdlib isolate | 6/6 pass | verified |
| Derived network intelligence | exact current `netintel/summary.go` with canonical flow/network/provider dependencies | 2/2 pass | verified |
| Interrupted-job recovery policy | exact current `recovery.go` + tests with established store/job stubs | 4 top-level tests pass, including active-descendant truth | verified |
| Conversion + shaping + comparator | exact current `convert.go`, `transform.go`, `roundtrip.go` with canonical proxyconfig source | 15 focused tests pass | verified |
| Generated URI/Base64/LumiNet JSON semantic re-ingest | generated-output round-trip tests | URI/Base64/canonical JSON pass | verified |
| VLESS explicit security serializer | exact proxyconfig serializer/parser isolated test | TLS + Reality cases pass | verified |
| UI/API authority characterization | `test-eighth-order-promotions.mjs` | 41 checks pass, including the Capability & Coverage Center evidence separation | verified |
| Touched TS/TSX parse/transpile | TypeScript 5.8.3 `transpileModule` | flow/conversion/recovery plus capability page/parser/router/layout surfaces clean | statically-validated |
| Go declaration integrity | repository standard-library checker compiled outside the Go 1.26 workspace and executed against target | 1,557 parsed Go files; 0 syntax errors; 0 duplicate active declarations on linux/windows/darwin/android selections | statically-validated |
| Focused ownership/structure | source structure, tooling surface, runtime-core, host-network, jobs, subscription, remote HTTP action gates | all pass | verified |
| Historical convergence preservation | post-refactor-160 and post-refactor-180 checkers using immutable successor baselines | both pass | verified |
| Source context | generated 122 `.context` files, then source-context checker | 122 required; 0 errors | verified |

Focused logs are retained in the release evidence bundle under `logs/`.

## Important negative-path evidence

### Flow authority

- An owner must declare coverage before a flow can be registered.
- Process/destination/close semantics beyond declared owner coverage are rejected.
- Close callback executes outside the registry mutex.
- Close failure restores the active state if the same generation still owns the record.
- Oversized multi-close is all-or-nothing: no prefix is closed before the request is rejected.
- Missing runtime owners are represented as negative coverage; the UI cannot infer host completeness.

### Capability coverage truth

- Registry availability, native-core linkage, flow-owner coverage, network-monitor health and provider-corpus freshness are returned as separate response dimensions.
- Flow coverage remains explicitly partial rather than host-complete.
- A stale or absent provider corpus remains visible and cannot be promoted to a healthy provider-attribution claim.
- The Capability & Coverage Center is read-only and owns no runtime/network/profile state.

### Network epochs

- Revisions advance only on meaningful address/route/link/MTU/flag identity changes.
- Failed capture retains last-good state and reports error.
- History is bounded; `history=0` returns no history.
- Subscriber delivery is coalesced.
- The monitor never becomes a route mutator or platform-network acquisition owner.

### Compatibility and transformations

- Input is local content; conversion does not fetch a URL-shaped string.
- Node/output/rule/pattern sizes are bounded.
- Detour cycles, ambiguity, dangling references and orphaning filter/limit operations fail closed.
- Strict conversion rejects first-pass unsupported/lossy semantics.
- A second strict gate re-ingests generated output and rejects parser, cardinality, semantic or detour-graph drift.
- The new gate found and fixed a VLESS TLS/Reality downgrade bug before release.

### Restart recovery

- Persisted proxy-test config is redacted rather than storing full credential-bearing URIs.
- Consequential or secret-bearing jobs are non-reconstructible.
- Interrupted source records are immutable.
- Recovery creates a new job with `recovered_from` lineage and requires explicit operator confirmation.
- An active descendant blocks a concurrent duplicate.
- Nothing auto-replays at daemon initialization.

### Automatic configuration mutation retry

Post-refactor-220 explicitly preserves the post-refactor-160 authority contract:

- default attempt budget 3;
- hard maximum 8;
- explicit `ExpectedRevision`/HTTP precondition forces one attempt;
- only revision conflicts are replayed;
- replay calls the pure configuration intent against a fresh authoritative snapshot;
- runtime/host side effects remain outside the retried config callback and occur after durable commit.

## Toolchain limits

The working environment has Go **1.23.2**, while the repository workspace declares Go **1.26.x** and attempts automatic 1.26.5 toolchain acquisition. Network toolchain download is unavailable. Therefore the full production Go workspace test/build matrix is not claimed from this environment. Standard-library-only changed packages were executed in isolated modules containing the exact current source.

Rust/Cargo and Gradle are unavailable. Full LumiCore Rust tests, Android Gradle build/tests, and Go↔Rust link tests are therefore not executed here. Global Node 22.16.0 and TypeScript 5.8.3 are available; touched TS/TSX syntax transpiles, while full frontend semantic typecheck/build remains dependent on the repository's locally absent package installation.

`iperf3` and `traceroute` executables are unavailable in the current container, so this wave does not create new runtime claims for those already-shipped post-160/post-180 diagnostics. Their prior source/test evidence remains inherited and their runtime absence is reported by the product rather than fabricated as success.

## Source freeze admission

The complete canonical `verify-repo` command list was executed against the expanded post-220 source in two bounded bands because the sandbox command-duration ceiling interrupts the monolithic target. Every command completed successfully when resumed at the exact unexecuted boundary. This includes source/context/topology, target/declaration integrity, all historical convergence gates through post-refactor-220, route/platform/native truth, FFI safety/coverage, convergence validators, peer convergence, and repository audit. The only repository-audit message is the inherited Android Gradle-wrapper warning documented above.

The source is admitted to immutable packaging only after regenerating the exact target delta and rerunning the post-refactor-220, topology, source-context, characterization, declaration-integrity and repository-audit gates on the final report bytes. Archive safety/member/hash verification, clean extraction, manifest comparison, and extracted-tree gates are release-stage evidence recorded in the release receipt. Any source-byte change after package freeze invalidates that evidence.
