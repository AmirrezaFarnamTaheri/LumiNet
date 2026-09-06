# Post-refactor-223 validation

## Claim boundary

This release is validated against the immutable post-refactor-222 source snapshot plus the 13 supplied donor archives. The working source is archive-derived and contains no `.git` metadata, so this validation does **not** claim correspondence to a remotely fetched Git branch/commit.

## Repository/source gates

Verified in the final source state before freeze:

- `check_source_structure.py`
- `check_source_context.py` — 125 required source contexts, 0 errors
- `check_tooling_surface.py` — 0 errors
- `verify_repository_topology.py` — baseline fully accounted, 0 errors
- `repo_audit.py` — 0 errors; one informational Android Gradle-wrapper warning
- frozen `check_post_refactor_222_convergence.py` — PASS against the post-223 successor baseline
- all eight focused post-refactor-223 successor gates — PASS
- `check_lumicore_abi.py`, `check_rust_ffi_refactor.py`, `check_ffi_runtime_safety.py` — PASS
- `check_mobile_product.py`, `check_host_network_ownership.py`, `check_runtime_core_ownership.py`, `check_subscription_ownership.py`, `check_peer_convergence.py` — PASS
- broader Python checker sweep: **72 PASS / 2 environment-bound FAIL**. The two failures are Graphify output (tool/output unavailable) and Cargo-based LumiCore link resolution (`cargo` unavailable).

## Control UI characterization

Nine dependency-free Node characterization scripts passed, **199 checks total**:

- contracts: 30
- eighth-order promotions: 41
- fifth-order feature promotions: 20
- post-refactor-222: 57
- post-refactor-223: 9
- PWA: 8
- seventh-order promotions: 12
- sixth-order promotions: 19
- transport: 3

The post-refactor-223 script verifies DNS reliability, transport truth, and DNS transport-integrity parsing/request/product behavior. Dedicated source gates additionally verify subscription-node UI and semantic command aliases.

## Exact-source Go behavior evidence

Sixteen isolated exact-source harnesses passed using the available local Go toolchain for dependency-free promoted slices:

1. adaptive-throttle alignment
2. host-route release
3. HTTP→SOCKS bridge
4. native async policy
5. scanner probe constants/execution
6. subscription failure classification
7. DNS transport integrity
8. DNS tunnel reliability
9. DNS delegation decisions
10. DNS delegation integration
11. strict REALITY TLS/hostname behavior
12. bounded scanner plan
13. subscription node catalogue
14. subscription runtime
15. transport truth
16. managed VPS layout transaction

The adaptive-throttle harness also cross-compiled successfully for `linux/386`, providing direct evidence for the 32-bit atomic-alignment fix.

## Toolchain/environment limitations

These are **not** represented as passing validation:

- Repository Go modules require Go >= 1.26.0. The host provides Go 1.23.2; automatic toolchain download is blocked by network/DNS policy. Full daemon `go test ./...` therefore cannot run here.
- Cargo/Rust is unavailable. Rust source/ABI changes are statically checked by repository ABI/runtime-safety gates, but no Cargo build/test is claimed.
- `graphify` is unavailable and `graphify-out/graph.json` is not present; no graph output was fabricated.
- Control UI `node_modules` is intentionally absent in the clean source tree. `npm run typecheck` cannot resolve `vite/client` and Node type definitions; dependency-free characterization scripts pass instead.
- Gradle is unavailable and the source archive does not contain an Android Gradle wrapper; no Android compile is claimed.

## Release verification requirement

After the source is frozen, the release process must:

1. generate an exact file manifest;
2. archive the frozen bytes once;
3. validate archive member safety before extraction;
4. independently extract to a clean directory;
5. compare every extracted file hash against the frozen manifest;
6. generate archive/source/evidence checksums and an external release receipt.

Any source byte change after freeze invalidates the release verification and requires rebuilding the artifact.
