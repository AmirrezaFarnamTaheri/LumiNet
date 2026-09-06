# LumiNet post-refactor 83-donor validation

## Scope

This validation starts from the frozen refactor-audited LumiNet baseline, closes F-014 through F-018, then converges 20 additional donor archives without rewriting the historical 63-donor evidence.

## Focused execution

- SSH identity + trusted provisioning exact-source harness: 100 race-enabled repetitions passed; `go vet` passed.
- Shared polling relay state/backoff exact-source harness: 100 race-enabled repetitions passed; `go vet` passed.
- Endpoint-pool admission exact-source harness: 100 race-enabled repetitions passed; `go vet` passed.
- Cross-platform Go declaration checker: 1,516 parsed files; 0 syntax errors; 0 duplicate active declarations on Linux/amd64, Windows/amd64, Darwin/amd64, Android/arm64.
- Rust FFI refactor checker: 42 ABI exports, 25 unsafe legacy exports, errors=0.
- Existing LumiCore ABI checker, FFI runtime-safety checker, and FFI dead-surface checker: errors=0.

## Canonical repository verification

`make verify-repo` was run with Python bytecode disabled on the final documented source state. The one-shot invocation completed every command through the ninth-order convergence gate and was terminated by the external tool timeout while the historical final-convergence checker was running; it had reported no failure before termination. The exact remaining Makefile tail beginning with final convergence was then executed command-for-command:

- final, ultimate, historical refactor, and post-refactor-83 convergence gates: errors=0
- route/platform/native-degraded/proxy liveness and pruning gates: errors=0
- proxy qualification ownership: errors=0
- LumiCore ABI + Rust FFI refactor/runtime-safety/dead-surface gates: errors=0
- native dormant surfaces + native verification coverage: errors=0
- LumiCore link unit tests: 5 passed
- convergence validation: errors=0
- peer convergence: unresolved_high_signal=0, errors=0
- repository audit: errors=0, warnings=1

The warning is inherited/environmental: the Android Gradle wrapper is absent locally; CI/release explicitly provisions Gradle 9.5.0.

## Historical and successor evidence

- original topology: 2442/2442 accounted, errors=0
- historical ultimate 63-donor convergence: errors=0
- historical refactor audit: errors=0 using the successor baseline
- post-refactor 83-donor convergence: 20 new donors, 456 archive members, 352 surfaces, 104 directories, 53 bounded modules, 1,646 normalized declarations, 30 fine semantic decisions, 83 new ledger records, errors=0

## Limitations

The repository declares Go 1.26.x while the local environment provides Go 1.23.2 and cannot fetch the declared toolchain/dependencies. Whole-workspace Go build/test is therefore not claimed. Changed Go behavior was exercised through dependency-isolated exact-source race harnesses plus repository source/governance gates.

Rust/Cargo/Miri are unavailable, so F-017 is statically validated rather than compiled/runtime-verified. External provider credentials, production relays, and deployment hosts were not exercised.
