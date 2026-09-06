# Refactor-pass validation

## Changed Go seams

The following dependency-isolated harnesses were refreshed from the final source files and executed 100 times under Go's race detector:

| Harness | Result | Additional static check |
|---|---|---|
| provisioning log/history | PASS ×100 | source syntax via repository checker |
| provisioning SSH bounded output/error redaction | PASS ×100 | `go vet` PASS |
| runtime engine transactional replacement/restore | PASS ×100 | `go vet` PASS |
| NAT active package | PASS ×100 | `go vet` PASS |
| serverless HTTP relay | PASS ×100 | `go vet` PASS |
| GSA relay | PASS ×100 | `go vet` PASS |
| WebTunnel PKI/pin trust and canonical relay adapter | PASS ×100 | `go vet` PASS |

The harnesses are intentionally dependency-isolated because the supplied repository declares a Go 1.26.x workspace while this environment provides Go 1.23.2 and cannot fetch the required newer toolchain/modules. The harnesses use exact current source for the changed owner under test plus minimal dependency stubs where needed; they do not establish whole-workspace Go 1.26 compatibility.

## Deterministic Go source integrity

A repository checker parses every Go source file and performs active top-level declaration collision checks for these build selections:

- linux/amd64 — zero duplicate declarations;
- windows/amd64 — zero duplicate declarations;
- darwin/amd64 — zero duplicate declarations;
- android/arm64 — zero duplicate declarations.

This checker specifically closes the deterministic compile-failure class found during this audit (GSA self aliases, NAT constant/type collisions, and the stale Android lab duplicate) without pretending to replace a full module build.

## Canonical repository verification

`make verify-repo` was executed on the final refactor source state. The one-shot tool invocation reached and passed:

- source structure/context/tooling;
- topology;
- LumiCore source purity;
- daemon/desktop/mobile/host reachability;
- Go target/declaration integrity;
- daemon/request/host-network/runtime/proxy ownership;
- scanner/telemetry/job/evasion/capability/subscription truth;
- remote HTTP action registry;
- every convergence gate from second-order through ultimate;
- the refactor successor gate;
- route truth and platform capability truth.

The external command runner timed out before the next Makefile command. No failure was reported before that timeout. The exact remaining Makefile tail was then executed individually with Python bytecode disabled and all checks passed:

- native degraded truth;
- proxy liveness/final pruning/qualification;
- LumiCore ABI, FFI runtime safety, FFI dead-surface, native dormant-surface and native verification coverage;
- LumiCore link unit tests;
- convergence validation;
- peer convergence;
- repository audit.

Final repository audit result: `errors=0`, with one environment warning that the Android Gradle wrapper is not present locally; CI/release explicitly provision Gradle 9.5.0.

A manual tail run initially omitted `PYTHONDONTWRITEBYTECODE` and created `scripts/checks/__pycache__`; the repository audit correctly rejected that task-created residue. It was removed, the tail was rerun with bytecode disabled, and the audit passed. No cache residue is permitted into the release.

## Historical and successor evidence

- Historical ultimate convergence: PASS, 63 donors / 8,223 donor surfaces / 662 adoption records / errors=0.
- Refactor successor gate: PASS, 2,588-file frozen baseline / 18 findings / 15 coverage rows / 13 remediation decisions / exact target delta / errors=0.
- Repository topology: PASS, 2,442/2,442 original baseline paths accounted.
- Remote HTTP action registry: PASS, 29 registered actions and zero raw Python mutations.

## Packaging rehearsal

Before final source freeze, a deterministic source-equivalent archive was built as a packaging rehearsal. It contained 2,896 tar members representing 2,595 file/symlink entries. Archive path/type/collision checks passed, clean extraction produced a byte-identical manifest, and the extracted copy independently passed the refactor/ultimate/topology/declaration/remote-action/runtime-core/host-network/repository-audit gates.

The immutable delivery archive is built after this document is frozen. Its final hash, tree digest, manifest comparison, and clean-extracted verification are recorded in the external release receipt and checksum artifacts so the source archive does not need a self-referential post-build edit.

## Unavailable verification

- Full Go 1.26.x workspace build/test: BLOCKED by local Go 1.23.2 and offline toolchain/dependency availability.
- Rust Cargo/clippy/test/Miri: BLOCKED because Rust/Cargo are unavailable.
- Android wrapper build: BLOCKED locally because the wrapper is absent; repository CI/release pins Gradle 9.5.0.
- Production-like external SSH/VPS/cloud environments: not exercised.

No blocked check is represented as verified.
