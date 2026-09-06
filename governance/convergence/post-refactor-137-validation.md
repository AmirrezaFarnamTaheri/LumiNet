# LumiNet post-refactor 137-donor validation

## Focused executable evidence

At the frozen implementation state, the HTTP serverless sequence tests passed 100 repetitions under Go's race detector for mismatch rejection and matching/legacy omission compatibility; `go vet` passed the exact-source relay harness.

The DoH admission/identity tests passed 100 race-enabled repetitions for first-waiter cancellation isolation, fail-fast unique-host admission, and transaction/question mismatch rejection; `go vet` passed the exact-source DoH harness.

The WhiteDNS domain-boundary test passed 100 race-enabled repetitions and `go vet` in an exact-source harness.

One aggregate final harness command exceeded the host execution timeout because all three 100x race suites were batched into a single shell. It is retained as an unverified timed-out invocation. The suites were then executed separately from their standalone module roots and passed; no timeout is represented as a test pass.

## Evidence validation

The convergence skill's current-schema validator passes the combined strict successor ledger at **4,740 records, 268 unique tests/decision anchors, 0 warnings**. Current donor-byte verification independently matches **8,408 regular files plus two captured symlink targets, 8,410/8,410, errors=0**.

Repository, declaration, historical successor, release-byte and checksum evidence is recorded in the final external release receipt after the source is frozen. Historical 117 evidence remains immutable; the 137 successor adds evidence rather than rewriting prior matrices.

## Toolchain boundary

This host has Go 1.23.2 while LumiNet declares Go 1.26.x/toolchain 1.26.5 and cannot fetch the full declared workspace toolchain/dependencies. Rust/Cargo/Miri are unavailable and the local Android Gradle wrapper is absent. No unexecuted full-workspace Go 1.26, Rust/Miri or Android result is represented as verified.

## Canonical repository verification

A monolithic `make verify-repo` run passed every command through `check_post_refactor_97_convergence.py` before the host execution ceiling interrupted the run while the 117-donor checker was starting. That invocation is recorded as timed out, not passing. The exact untouched Makefile tail beginning at the 117-donor checker was then executed command-for-command. All functional/governance checks passed; the first tail run exposed one task-created `scripts/checks/__pycache__` directory from an earlier syntax check. Only that transient cache was removed. The affected successor/convergence/repository checks were rerun and ended at `errors=0`; repository audit retains the single inherited warning that the local Android Gradle wrapper is absent while CI/release provisions Gradle 9.5.0.
