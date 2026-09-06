# Post-refactor-225 validation report

## Evidence and convergence

- `make post-refactor-225-evidence` executed twice from original donor ZIPs; all generated post-refactor-225 evidence artifacts were byte-identical across the two runs.
- dedicated convergence checker: **42,693 assertions passed** after each final evidence regeneration.
- current-wave denominator: 23 donors / 1,548 surfaces / 323 directories / 7,255 symbols / 1,133 semantic records.
- all-history overlay: 38 donors / 2,461 surfaces / 9,511 symbols / 202 subtrees / 159 UI-product surfaces.
- exact successor delta is recomputed from a 2,979-file immutable post-refactor-224 baseline inventory.

## Focused executable Go verification

Executed under local Go 1.23.2 in isolated exact-source modules because the repository requires Go 1.26.5 and outbound toolchain download is unavailable:

1. 225 diagnostics policy suite — PASS.
2. bounded CDN candidate generation — PASS.
3. Wintun policy bounds — PASS.
4. complete stdlib-only proxyconfig/share-link parser package — PASS.
5. TUIC v5 command codec bounds/truth suite — PASS.
6. TLS ClientHello/SNI fragmentation package — PASS after fixing a missing `encoding/binary` import and replacing an invalid historical pattern-only ClientHello fixture with a structurally valid fixture.

The focused execution also caught and fixed a duplicate package test helper that would have broken Go declaration integrity on Linux, Windows, macOS and Android.

## Frontend/product verification

- complete dependency-free Control UI characterization chain — PASS: **321 checks total**, comprising historical contracts, transport, PWA, feature-promotion, sixth/seventh/eighth order, post-refactor-222, post-refactor-224 and **101 post-refactor-225 checks**.
- TypeScript 5.8.3 compiler parse/no-check pass over all Control UI `.ts/.tsx` source — PASS.
- full semantic `tsc` is environment-blocked because `node_modules` is intentionally absent; the first missing package is `vite/client`. This is not reported as a successful semantic typecheck.

## Canonical repository verification

The complete `verify-repo` recipe was executed in Makefile order using bounded command bands so long historical checks receive conclusive exit statuses. All constituent checks pass after the documented descendant-history fixes. This includes source/context/tooling/topology, Rust/Go source reachability, mobile/desktop ownership, four-platform Go declaration integrity, runtime/host/proxy/evasion/subscription truth, historical convergence through 224, current 225 convergence, route/platform/native truth, ABI/FFI coverage, convergence validation, peer convergence and final repository audit.

Repository audit result: 0 errors; one environment warning that the local Android Gradle wrapper is absent and CI/release provisions Gradle 9.5.0.

## Historical preservation repairs

- third-wave SNI checker follows the 219-byte bound to its canonical shared `sni_validation.go` owner rather than requiring duplicate ownership in the scanner.
- post-refactor-224 delta reconstruction uses the exact frozen pre-225 successor inventory.
- Wave-24 TLS-fragment byte-equivalence history is preserved through a frozen pre-225 hash/normalized-hash anchor plus explicit 225 descendant-delta accounting.

## Toolchain claim boundary

Available: Go 1.23.2 local, Node 22.16.0, npm 10.9.2, TypeScript 5.8.3.

Unavailable or blocked here: repository-required Go 1.26.5 (toolchain download blocked by network), Cargo/rustfmt, local Android Gradle wrapper, and full frontend dependency installation. Therefore this report claims verified source behavior for the executed isolated packages and repository checkers, but does not claim a full native Go/Rust/Android/frontend production build.

## Release status

All source/evidence/canonical repository gates described above are green. Source release packaging remains the only open step: rescan task-created residue, freeze the exact tree, build immutable archives once, and independently extract/compare every member before issuing the final receipt.
