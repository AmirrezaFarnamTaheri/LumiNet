# Ninth-order convergence validation

## Claim boundary

This report validates the ninth-order source changes against the frozen eighth-order LumiNet baseline and the 20-donor evidence corpus. Runtime claims are limited to tests actually executed in this container. The repository declares Go 1.26.0 / toolchain Go 1.26.5, while the available local toolchain is Go 1.23.2 and the environment is offline; dependency-bound whole-workspace Go builds are therefore not claimed. Changed Go contracts were exercised in dependency-isolated harnesses with the race detector. Rust is unavailable in this container and ninth-order introduces no Rust runtime source.

## Evidence/accountability gates

- Archive admission: 20/20 donor ZIPs passed path, duplicate, case-collision, link and bounded-expansion checks before extraction.
- Donor accountability: 2,379 archive members; 1,954 file/symlink surfaces; 425 directories; 137 recursively bounded module groups; 8,676 parsed symbols/declarations.
- Decision graph: 168 adoption-ledger records, including 31 fine-grained semantic decisions and 8 supersession/composition groups.
- No splittable module group exceeds 100 surfaces.
- Ninth-order convergence gate: `errors=0`.
- Eighth-order historical gate under the ninth-order successor baseline: `errors=0`.
- Repository topology: `2442/2442` original-baseline surfaces accounted, `errors=0`.
- Peer convergence: `unresolved_high_signal=0`, `errors=0`.

## Changed capability validation

### Transactional Caddy configuration generation

Isolated harness: `testharness/caddy`.

Validated behavior includes semantic hashing, strict JSON admission, unchanged-plugin reuse, changed-plugin replacement, partial-stage rollback, post-commit retirement, immutable config reads, non-blocking readers, cleanup-error committed-state behavior, whole-config compare-and-swap conflict detection, and bounded configuration validation.

- normal `go test ./...`: verified
- `go vet ./...`: verified
- `go test -race -count=100 ./...`: verified

### WARP quality selection and bounds

Isolated harnesses: `testharness/warp-scanner` and `testharness/warp-handshake`.

Validated behavior includes repeated probing, loss measurement, median successful RTT, loss-first ranking, zero-loss stop semantics, candidate/concurrency/attempt/timeout/noise bounds, and rejection of direct noise requests outside the scanner safety envelope before network I/O.

- scanner normal tests: verified
- scanner `go vet`: verified
- scanner `go test -race -count=100 ./...`: verified
- handshake dependency-isolated normal/race compilation: verified
- handshake `go vet`: verified

### Network diagnostics

Isolated harnesses: `testharness/speedtest-metrics` and `testharness/speedtest-runner`.

Validated behavior includes minimum ping, median latency, adjacent-sample jitter, packet loss, stability classification, request byte/time/sample bounds, cancellation, redirect bounds, credential-free HTTP(S) redirects, Content-Length rejection, and bounded reads when an origin ignores Range.

- metrics normal tests + `go vet`: verified
- metrics `go test -race -count=100 ./...`: verified
- runner normal tests + `go vet`: verified
- runner `go test -race -count=100 ./...`: verified

### Advisory profile entitlement projection

Isolated harness: `testharness/profile-entitlement`.

Validated behavior includes active/warning/exhausted/expired/unknown precedence, quota/expiry knownness, low-quota and expiry warnings, clamped percentages, negative-counter normalization and saturating provider-usage addition on `int64` overflow. The projection remains advisory and is not connectivity authority.

- normal tests + `go vet`: verified
- `go test -race -count=100 ./...`: verified
- control-UI contract characterization: 30 checks passed
- isolated `Profiles.tsx`/contract TypeScript compile: verified

## Repository-wide governance verification

The canonical `make verify-repo` command was executed until the tool-call wall after the eighth-order convergence gate, with no reported error. Execution resumed from the ninth-order gate and ran every remaining Makefile verification command individually. All completed with `errors=0`, including route/platform truth, native/proxy/ABI/FFI checks, native verification coverage, convergence validation, peer convergence and repository audit.

`repo_audit.py` reports one inherited/environmental warning: the Android Gradle wrapper is absent locally while CI/release explicitly provisions Gradle 9.5.0. No ninth-order repository error is reported.

## Formatting/static checks

All ninth-order Go delta files are `gofmt` clean. All dependency-isolated Go harnesses pass `go vet`.

## Toolchains

- Go available: 1.23.2; repository declares Go 1.26.0 / toolchain 1.26.5.
- Node: 22.16.0.
- npm: 10.9.2.
- TypeScript compiler: 5.8.3.
- Python: 3.13.5.
- GNU Make: 4.4.1.
- Rust/Cargo: unavailable.

## Limitations

- Whole-workspace dependency-bound Go execution is not claimed because the required Go 1.26.5 toolchain/modules cannot be fetched in the offline container.
- Rust/native runtime suites were not executed; ninth-order adds no Rust source and repository static/native-governance gates pass.
- Android application builds were not executed because the local Gradle wrapper is absent; this is an existing repository-audit warning, not a ninth-order regression.
- Credentialed external services, real WARP endpoints, real Cloudflare APIs and production network environments were not exercised. Tests use local/deterministic harnesses for the changed contracts.

## Final delta

After adding this validation artifact, the expected ninth-order source delta is 37 paths relative to the frozen 2,522-file eighth-order baseline. `ninth-order-target-delta.csv` is regenerated after this report and is the authoritative path/hash listing.
