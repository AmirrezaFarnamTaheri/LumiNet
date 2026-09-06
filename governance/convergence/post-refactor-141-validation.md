# LumiNet post-refactor 141 validation

## Verification boundary

The frozen 137-donor source/evidence pair was re-hashed and independently extracted before this wave. The four new archives were CRC/path/type/case checked before extraction; no outer symlink or special member was materialized. Recursive nested-archive inspection covered 92 archive nodes and 10,145 members with no unsafe path, link, special-type, or CRC finding.

## Current-wave evidence

- New donor surfaces: 6,534 / 6,534 re-hashed successfully against the extracted donor roots.
- New bounded accountability groups: 333, all at most 100 surfaces.
- New normalized donor-owned declarations: 38,774.
- Exact-byte overlap with the frozen 137 corpus: 66 surfaces; overlap carries no duplicate semantic credit.
- Current-wave ledger: 386 records / 53 unique test-or-decision anchors / 0 warnings under the convergence ledger validator.
- Strict combined ledger: 5,126 records / 321 unique test-or-decision anchors / 0 warnings.

## API client-IP repair

The API router now calls `SetTrustedProxies(nil)` during construction and fails closed if that configuration unexpectedly errors. This keeps direct peer address authoritative for the existing `ClientIP()`-based rate limiter and request logger unless a reviewed proxy-trust policy is introduced explicitly.

The repair followed a RED -> GREEN source contract in `scripts/checks/check_api_direct_client_ip.py`: before the change the checker reported the missing direct-peer policy and missing fail-closed handling; after the change it reports `api direct-client-ip trust: errors=0`.

A full API package build/runtime test is not executable in this environment: the workspace declares Go 1.26.x/toolchain 1.26.5, while the available local Go toolchain is 1.23.2 and the declared toolchain cannot be fetched here. The repair is therefore **statically validated/source-contract verified**, not runtime-verified.

## Repository verification

The dependency-free Go declaration checker parsed 1,524 Go files with zero syntax errors and zero active duplicate declarations for Linux, Windows, macOS, and Android target selections.

The canonical `make verify-repo` invocation was bounded by the host execution ceiling. It completed every command through ninth-order convergence successfully, then was terminated while beginning `check_final_convergence.py`. This monolithic invocation is deliberately recorded as **unverified due to execution timeout**, not as passing.

The exact untouched Makefile tail from `check_final_convergence.py` onward was then executed command-for-command on the same source state and passed:

- final, ultimate, and refactor convergence;
- frozen 83-, 97-, 117-, and 137-donor gates;
- API direct-client-IP source contract and 141-donor convergence gate;
- route/platform/native/proxy ownership and pruning gates;
- LumiCore ABI and Rust FFI static-safety gates;
- five LumiCore link tests;
- global convergence validator;
- peer convergence (`unresolved_high_signal=0`, `errors=0`);
- repository audit (`errors=0`, one inherited warning: local Android Gradle wrapper absent; CI/release provisions Gradle 9.5.0).

## Successor gate

`check_post_refactor_141_convergence.py` reports:

`donors=141 waves=63+20+14+20+20+4 surfaces=42277 directories=7210 modules=4789 symbols=143859 semantics=337 records=5126 nested_new=92 delta=36 errors=0`

Historical 83/97/117/137 convergence gates remain green at their frozen release boundaries.

## Remaining environment limitations

- Local Go: 1.23.2; workspace/toolchain requirement: Go 1.26.x / toolchain 1.26.5; remote toolchain fetch unavailable here.
- Rust/Cargo/Miri unavailable; Rust FFI claims remain static-only where previously documented.
- Local Android Gradle wrapper absent; repository audit preserves this as an inherited warning.
- No unavailable toolchain or unexecuted full-workspace result is represented as passing.
