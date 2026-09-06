# Post-refactor-222 validation

## Claim boundary

This validation covers the exact post-refactor-222 source tree and its convergence evidence. Runtime claims are limited to what was actually executable in the available environment. Full daemon-module and Rust-native test/build admission could not be executed because the host provides Go 1.23.2 while the repository requires Go 1.26.x, Cargo/Rust is unavailable, and the offline frontend tree does not contain the complete installed type-definition dependency set. Those limitations are not converted into passes.

## Evidence/accountability gates

- `python3 governance/convergence/post-refactor-222-verify.py` — **VERIFIED**: 81 semantic records, 6,253 current donor file/symlink surfaces, 13,006 extracted symbols, 23 unique current donors, and 62 accumulated donor rows close bidirectionally. Original donor ZIP member bytes are re-hashed, including symlink target bytes.
- `python3 scripts/checks/check_post_refactor_222_convergence.py` — **VERIFIED**: current donor denominators, ledger identities, target/test anchors, historical bridges, archive aliases, promoted-plane guardrails and exact target delta all pass.
- `python3 scripts/checks/check_post_refactor_220_convergence.py` — **VERIFIED** after successor-baseline repair: five explicit post-refactor-221 additions are accounted without restoring superseded runtime code.
- Repository topology/source-context/declaration/ownership/convergence gates through `check_refactor_audit.py` executed successfully in the long `make verify-repo` run before the command-level timeout. The remaining `verify-repo` commands were then executed explicitly and passed after the historical-delta repair and topology cleanup.
- `python3 scripts/checks/repo_audit.py` — **VERIFIED** with 0 errors. One environment/repository warning remains: the Android Gradle wrapper is not present; CI/release declares Gradle 9.5.0 provisioning.

## Product/UI validation

`npm test` in `src/packages/control-ui` — **VERIFIED**, 190 characterization checks:

- contracts: 30
- transport: 3
- PWA: 8
- fifth-order feature promotions: 20
- sixth-order promotions: 19
- seventh-order promotions: 12
- eighth-order promotions: 41
- post-refactor-222 convergence: 57

The post-222 checks cover peer-planner product exposure, endpoint evidence, command palette/recents, appearance, Health/redacted export, live-log tail control, subscription deep-link inspect/prefill and negative authority boundaries.

`npm run typecheck` — **ENVIRONMENT-BLOCKED**, not passed. TypeScript reports missing installed type definitions for `vite/client` and `node`. The transient partial `node_modules` directory was removed instead of being shipped.

## Go behavior validation

The repository Go workspace requires Go >= 1.26.0; the available local compiler is Go 1.23.2 and network toolchain download is unavailable. Full module tests are therefore **UNAVAILABLE** in this environment.

To avoid replacing execution evidence with static inspection, exact final source files were copied into isolated Go 1.23 harnesses for semantics that do not depend on the newer module/toolchain surface:

- endpoint planner + tests — **VERIFIED**
- peer discovery planner + BEP42 + canonical `netpolicy` subset/tests — **VERIFIED**
- signed update admission/staging source + tests — **VERIFIED**
- subscription deep-link parser + tests — **VERIFIED** using a minimal harness shim for the existing canonical profile URL validator because the full subscription package cannot be loaded under the host toolchain

All four `go test ./... -count=1` harness runs passed from refreshed copies of the final source.

`gofmt -l` across all post-222 changed Go source/test files returned no paths.

## Rust/native validation

Cargo/Rust is unavailable on this host, so `cargo test`, `cargo clippy`, native release linking and full ABI runtime execution are **UNAVAILABLE**. The repository's static ABI/FFI gates did execute and pass:

- `check_lumicore_abi.py`
- `check_rust_ffi_refactor.py`
- `check_ffi_runtime_safety.py`
- `check_ffi_dead_surface.py`
- `check_native_dormant_surfaces.py`
- `check_native_verification_coverage.py`
- `test_lumicore_link.py`

## Historical convergence regression chain

The following wave gates executed successfully in this session (some as part of the long repository gate, some explicitly after its timeout): second-order, third-wave runtime/convergence, fourth, fifth, sixth, seventh, eighth, ninth, final, ultimate, refactor audit, post-refactor-83, -97, -117, -137, -141, -160, -180, repaired -220, and current -222. Global `validate_convergence.py` and `check_peer_convergence.py` also passed.

The seventh-order chain exposed a historical test-anchor regression during this pass. The endpoint invalid-input test retained its historical `TestBuildEndpointPoolPlanRejectsDuplicateAndInvalidQuota` anchor while preserving the newer jitter/loss validation cases.

## Omission and negative coverage

`post-refactor-222-omission-audit.md` is the saturation audit. It accounts for all 6,253 current surfaces, 20 archive symlinks and 13,006 symbols, and explicitly distinguishes exact historical evidence (4,960 current surfaces) from reopened material (1,293).

High-risk negative evidence is represented by guardrail/rejection records rather than operationalized offensive behavior. CAPTCHA solving, Tor deanonymization, active fake-infohash/findspies crawling, torrent freerider/content streaming, broad firewall reset, weak custom crypto/secret persistence and root/ADB/fastboot device mutation are not promoted into executable LumiNet capabilities.

## Residual limitations

1. Full Go 1.26.x workspace test/build was not executable here.
2. Cargo/Rust/native build/test was not executable here.
3. Frontend TypeScript build/typecheck is blocked by missing installed type definitions in the offline source tree.
4. Credential/external-service-dependent paths and platform-specific native runtime behavior were not live-exercised.
5. Android local wrapper-based build is unavailable in this tree; the repository documents CI/release Gradle provisioning.

These limitations are environmental/runtime evidence gaps. They do not invalidate the exact source/evidence/accountability, UI characterization, isolated Go semantics, static ownership/topology, ABI/FFI or archive-integrity claims that were actually verified.
