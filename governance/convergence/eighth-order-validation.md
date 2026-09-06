# Eighth-order convergence validation

Validation status vocabulary follows the convergence contract: **verified** means the check executed successfully; **statically-validated** means the relevant source/evidence invariant was inspected mechanically without executing the full runtime; **toolchain-blocked** is an environment limitation and is not counted as a passing runtime claim.

## Evidence and omission gates

| Check | Status | Result / claim boundary |
|---|---|---|
| Archive validation for target + 23 donors | verified | 24/24 archives rejected no absolute paths, `..` traversal, duplicate members, case collisions, device nodes, or decompression-bound violations. Donor symlinks remain explicitly accounted for. |
| Donor surface accountability | verified | 23 donors; 7,177 archive members; 6,057 donor files/symlinks; 1,091 directories; 395 recursively bounded accountability modules; 9,072 parsed declarations/symbols; 424 adoption/evidence records. |
| Anti-umbrella module split | verified | Every splittable recursive accountability module is <=100 donor surfaces. |
| Seventh-order historical layering | verified | `check_seventh_order_convergence.py`: donors=10, members=17,400, directories=5,605, surfaces=11,785, modules=126, symbols=31,264, records=55, supersession=14, baseline=2,478, changes=60, errors=0. |
| Source structure | verified | roots=6, bands=10, cross-band edges=34, errors=0. |
| Source context | verified | required=118, errors=0. |
| Remote HTTP mutation registry | verified | actions=29, constructors=17, dynamic wrappers=3, Python raw mutations=0, mutation=13, query-over-post=6, side-effect=8, stream-transport=2, errors=0. |
| Request-context ownership | verified | errors=0. |
| Telemetry truth | verified | errors=0. |
| Host-network ownership | verified | errors=0. |

## Executable eighth-order slices

All commands below used the locally available Go 1.23.2 toolchain with automatic toolchain download disabled where necessary.

| Capability | Validation | Status |
|---|---|---|
| Remote mutation retry executor | `GO111MODULE=off GOTOOLCHAIN=local go test ./src/apps/daemon/internal/foundation/remoteaction -count=1` | verified |
| Remote mutation retry race safety | same package with `-race` | verified |
| Bounded DoH HTTP cache | dependency-free file-list tests covering bounded TTL/LRU ownership, 5xx non-caching, stale-on-refresh-failure, same-key miss coalescing, malformed GET rejection, and GET/POST canonical-key equivalence | verified |
| Bounded DoH HTTP cache race safety | same file-list suite with `-race` | verified |
| Weighted DoH proxy | dependency-free file-list tests covering capacity, empty providers, concurrent provider selection, and expiry | verified |
| Weighted DoH proxy race safety | same file-list suite with `-race` | verified |
| Process supervisor recovery | file-list tests covering stable-ready debt reset and rolling failure-window pruning | verified |
| Process supervisor race safety | same file-list suite with `-race` | verified |
| Failover resolver hardening | dependency-isolated harness using target source plus minimal interface-compatible GeoIP/singleflight stubs; tests cover empty-provider fail-closed, cache bound, client replacement snapshots, and provider reconfiguration | verified |
| Failover resolver race safety | isolated resolver suite with `-race` | verified |

## Repeated stress/flake probes

The concurrency-sensitive eighth-order tests were repeated after all governance fixes and final formatting: remote mutation executor coordination/capacity/cancellation 100 times; DoH failure-admission/stale/coalescing/capacity 100 times; weighted DoH provider concurrency/empty-set/bounded-cache behavior 100 times; process-supervisor stable-run/history pruning 100 times; and all four isolated failover-resolver hardening tests 25 times under the race detector. All repetitions passed.

## Mutation-retry negative invariants

The automatic retry implementation is validated against the following safety constraints:

- `SingleAttempt` mutations are never replayed automatically, including after a provider rate-limit response.
- Only canonical action identifiers key shared cooldown state; full URLs, query strings, tokens, bodies, and secret-bearing request material are never retained in the cooldown map.
- Cooldown memory is hard-bounded and evicts old action state.
- A caller waiting on shared cooldown exits on context cancellation before issuing a request.
- Retryable ambiguous mutations retain the existing `ReconcileBeforeRetry` contract instead of blindly replaying side effects.
- Retry counts remain hard-capped; cross-call coordination does not create an unbounded retry loop.
- Operator telemetry is aggregate and secret-free.

## DNS resilience negative invariants

- Upstream HTTP failures are not admitted to the DNS cache.
- Stale data is served only after refresh failure and only inside the configured stale window.
- Cache capacity is hard-bounded and LRU eviction is centralized in one primitive.
- Same-key concurrent cache misses are coalesced rather than stampeded upstream.
- Malformed/oversized GET cache keys are rejected before allocation-heavy decoding or upstream work.
- Provider lists are snapshotted under lock; empty provider sets fail closed rather than panicking.
- Shared HTTP clients are replaced by snapshots rather than mutated concurrently in place.
- Cache-maintenance goroutines have caller-owned cancellation.

## Canonical repository verification

- `verify_repository_topology.py`: 2,442/2,442 original baseline paths accounted; 1,386 byte-identical, 595 reviewed transforms, 461 retired; errors=0.
- Convergence waves 2 through 8: every gate errors=0. The eighth-order gate reports 23 donors, 7,177 archive members, 1,091 directories, 6,057 surfaces, 395 bounded accountability modules, 9,072 symbols, 424 ledger records, 8 supersession groups, 2,502 baseline paths, and 37 exact target-delta paths.
- Current peer convergence: 8 historical donors, 3,320 archive members, 2,979 surfaces, 7,351 symbols, 2,094 high-signal symbols, 0 unresolved high-signal items, 110 semantic records, 3,089 ledger records, errors=0.
- Repository architecture/authority/truth/pruning/FFI/native checks executed by `verify-repo`: errors=0.
- `test_lumicore_link.py`: 5 tests passed.
- `validate_convergence.py`: adoption_records=357, surface_records=395, residual_classes=12, archive_retirements=47, errors=0.
- `repo_audit.py`: errors=0, warnings=1 (local Android Gradle wrapper absent; CI/release explicitly provisions Gradle 9.5.0).

## Toolchain and integration limits

The target workspace declares `go 1.26.0` and `toolchain go1.26.5`. The execution environment has Go 1.23.2 and no network path to `proxy.golang.org`, so the declared Go toolchain and missing external module dependencies cannot be downloaded. A full `internal/networking/dns` package test therefore cannot be executed in this container; the attempted offline package run failed while resolving external modules rather than at compilation of the changed source. The dependency-isolated resolver suite above closes the new resolver-specific behavioral/race claims but is not represented as full-package integration proof.

`cargo` is unavailable in the container, so pre-existing Rust/lumicore behavior was not re-executed. No eighth-order runtime implementation was added to the Rust plane.

The canonical `make verify-repo` sequence was verified in two execution segments because the single long-running invocation hit the tool-call timeout while entering `check_native_dormant_surfaces.py`, after every preceding command had reported success. The remaining Makefile commands were then executed verbatim: native dormant-surface coverage, native verification coverage, the five `test_lumicore_link.py` unit tests, historical convergence validation, peer convergence, and `repo_audit.py` all completed successfully. `repo_audit.py` emitted one pre-existing environment/tooling warning: the Android Gradle wrapper is absent locally, while CI/release provisions Gradle 9.5.0. No repository verification error remains.

## Evidence logs

The convergence workspace retains exact logs outside the source tree under `/mnt/data/luminet_convergence/evidence/`, including `archive-validation.json`, `validation-supporting-checks.log`, `validation-focused-go-final.log`, `validation-resolver-isolated-race-final.log`, and the full-package offline dependency-resolution failure log.
