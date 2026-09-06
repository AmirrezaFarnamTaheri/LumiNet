# Post-refactor-226 validation report

## Evidence regeneration and convergence

The current-wave evidence is regenerated from the 14 original donor ZIPs. The dedicated checker independently reopens the archives and verifies path/member safety, CRC, archive-to-extracted byte equality, all 1,299 current surfaces, 258 directory/root Merkle records, 15,975 definition backlinks, 893 semantic records and unique acceptance anchors, the 52-donor all-history overlay, exact frozen-baseline delta, protocol/security guards, product placement and automatic mutation retry invariants.

Dedicated result after final pre-report regeneration: **69,338 assertions passed**.

Current-wave denominator: 14 donors / 1,557 ZIP members / 1,299 surfaces / 244 subdirectories / 15,975 definitions / 893 semantic records / 745 focused high-signal file records with zero unresolved focused leaves.

All-history overlay: 52 donors / 3,760 surfaces / 25,486 definitions / 284 module/subtree groups / 2,317 high-signal surfaces / 161 UI-product surfaces.

## Executable Go evidence

The repository pins Go 1.26.5 and the host cannot reach the Go toolchain download endpoint. Full workspace Go package execution is therefore environment-blocked rather than represented as a pass.

Exact current source was copied into Go-1.23-compatible isolated harnesses and executed:

1. six post-refactor-226 planning contracts — PASS (6/6 tests);
2. complete stdlib-only `networking/proxyconfig` package, including SS2022 admission — PASS;
3. focused WireGuard/MWGP receiver-index/obfuscation policy semantics — PASS.

The planner harness initially caught a stale unused variable in `local_ruleset_plan.go`; the source was corrected and the same executable harness rerun green.

## Frontend/product evidence

- complete dependency-free Control UI characterization chain — PASS: **390 assertions**, comprising the prior 321 through post-refactor-225 plus 69 post-refactor-226 checks;
- modified TS/TSX planner/parser/page surfaces — PASS under TypeScript 5.8.3 transpile/parser validation;
- full semantic project typecheck — environment-blocked because task-created dependencies are not retained and installed `vite/client` / `node` type packages are absent. This is not reported as a pass.

The 226 UI gate checks API/handler reachability, typed result parsing, natural Rules/Settings/Health/Connections/Operations placement, and absence of hidden HTTP/process/file-write authority in the new planner handlers.

## Canonical repository verification

The `verify-repo` recipe was executed in Makefile order. The monolithic invocation reached the host command ceiling after the post-refactor-83 gate; the untouched tail was then executed in bounded command bands with conclusive exit statuses.

All constituent checks pass after two explicit successor-history repairs:

- third-wave runtime preserves its original `ss_server.go` assertion on pre-226 trees, while 226+ verifies the explicit retirement plus maintained core-manager/SS2022 successor contract;
- generic peer convergence accepts a missing historical target only through an exact frozen 225->226 deletion receipt; other missing paths remain failures.

Green gates include source/context/tooling/topology, Rust source purity, daemon/desktop/mobile reachability and ownership, seven Go target selections, four-platform Go declaration integrity, runtime/host/proxy/evasion/subscription truth, historical convergence through 225, post-refactor-226 convergence, route/platform/native truth, LumiCore ABI/FFI checks, 22 native verification-coverage checks, five LumiCore link tests, global convergence validation, peer convergence, and repository audit.

Repository audit: **0 errors, 1 warning** — no local Android Gradle wrapper is checked in; CI/release explicitly provisions Gradle 9.5.0.

## Source structure and topology

- source context: 126 required `.context` files / 0 errors;
- source structure: 6 roots / 10 bands / 35 cross-band edges / 0 errors;
- historical topology: 2,442/2,442 baseline paths accounted, 1,349 byte-identical, 610 reviewed transformations, 483 retired, 0 errors;
- Go declaration checker: 1,624 parsed Go files, 0 syntax errors, 0 duplicate active declarations on linux/amd64, windows/amd64, darwin/amd64 and android/arm64.

## Toolchain claim boundary

Available locally: Node 22.16.0, npm 10.9.2, TypeScript 5.8.3, Java 21. The repository-requested Go 1.26.5 cannot be downloaded in this environment. Cargo/rustfmt are unavailable. A local Gradle wrapper is absent. Therefore native/runtime claims are limited to the source checkers and exact-source executable subsets listed above; no unavailable build is represented as successful.

## Release gate

Before packaging, regenerate the 225->226 byte delta after these durable reports, rerun the 226 checker and repository audit, remove only task-created residue, freeze the exact source manifest/tree identity, and verify deterministic ZIP/tar payloads independently member-by-member.
