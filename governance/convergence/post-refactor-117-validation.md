# LumiNet post-refactor 117-donor validation

## Focused executable evidence

At the frozen implementation state, the mobile TUN/SOCKS repair passed 100 repetitions under Go's race detector for: IPv6 SOCKS UDP relay parsing, concurrent single-winner association installation, complete-write handling, and context-bounded association setup. `go vet` passed the exact-source mobile harness.

The VLESS/WebSocket response-state tests passed 100 race-enabled repetitions in both the focused helper harness and a full modified proxy-file compile harness: one-time preface consumption, split-preface handling without recursion, and wrong-version rejection. `go vet` passed both harnesses.

The relay WebSocket wrapper passed 100 race-enabled repetitions of an actual WebSocket round-trip/net.Conn contract test and an oversized-frame/read-limit test, plus `go vet`.

One failed validation invocation is intentionally preserved in the focused log: the first final rerun launched Go from the parent directory and failed because no root `go.mod` exists. Re-execution from each harness module root passed; this is classified as a harness invocation error, not a source failure.

## Inherited test behavior

`TestTun2SocksAdapter_DNSUsesSecureForwarder` is intermittently failing in a Go-1.23 dependency-isolated harness. The same failure reproduces against the frozen 97 source, so it is classified as inherited and is not suppressed, weakened, or counted as current repair evidence.

## Toolchain boundary

This host has Go 1.23.2; LumiNet declares Go 1.26.x and the environment cannot fetch that toolchain/workspace dependencies. Rust/Cargo/Miri are unavailable and the local Android Gradle wrapper is absent. Consequently no full-workspace Go 1.26, Rust/Miri, or Android execution is claimed here.

## Governance and release gates

`check_post_refactor_117_convergence.py` is the successor evidence/source gate and `check_post_refactor_97_convergence.py` is frozen to the exact 97-donor successor baseline. The 83-, 97-, and 117-donor gates pass at their preserved 51-path, 33-path, and current 44-path boundaries respectively.

The canonical `make verify-repo` passed every command through eighth-order convergence before the host execution ceiling terminated the monolithic process. That timeout is not represented as a pass. The exact untouched Makefile tail was then executed command-for-command from ninth-order convergence onward and passed, including final/ultimate/refactor convergence, all three successor gates, route/platform/native/proxy ownership, LumiCore/Rust-FFI static checks, five link tests, convergence validation, peer convergence with zero unresolved high-signal items, and repository audit. The repository audit has one inherited warning: the local Android Gradle wrapper is absent while CI/release provisions Gradle 9.5.0.

The convergence skill's ledger validator passes the current wave at **1,235 records / 60 unique tests / 0 warnings**. It also passes the strict combined successor overlay at **4,091 records / 199 unique tests / 0 warnings**. The latter uses 74 mechanical historical evidence-pointer normalizations while preserving the frozen 97 ledgers unchanged.

Every current-wave donor surface was rehashed against the extracted donor evidence: **6,742 regular files plus six captured symlink targets, 6,748/6,748 matched, errors=0**. The dependency-free declaration checker parses **1,522 target Go files** with zero syntax errors and zero active duplicate declarations on Linux/amd64, Windows/amd64, Darwin/amd64, and Android/arm64 selections.
