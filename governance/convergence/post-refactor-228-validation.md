# Post-refactor-228 validation

Validation is risk-proportional and separates executable proof from static review.

Executed on the final candidate source:
- isolated Go planner harness, uncached: PASS; covers extended rules, routing policy groups, browser handoff, gateway presets, WireGuard index translation, SNI self-loop, and worker protocol/recovery contract;
- isolated full proxyconfig package harness, uncached: PASS; covers Shadowsocks core compatibility and external-core runtime truth;
- isolated NodeCatalogue + proxyconfig harness, uncached: PASS; covers credential-redacted runtime compatibility;
- mutation retry authority checker: **1,847 assertions, PASS**;
- post-refactor-228 convergence checker: **109,122 assertions, 0 errors**;
- post-refactor-227 successor checker: **31,289 assertions, 0 errors**;
- full control-ui characterization suite: **526 checks, PASS**;
- TypeScript 5.8.3 parse/transpile of the seven modified TS/TSX surfaces: 0 errors; full `tsc --noEmit -p tsconfig.json`: PASS;
- Go declaration integrity under local Go 1.23.2 with `GOWORK=off`: **1,632 files parsed, 0 syntax errors, 0 active duplicate declarations** across linux/amd64, windows/amd64, darwin/amd64, and android/arm64;
- fresh rerun of 226 evidence generator reproduced exact 15,975 definitions / 1,299 files / 893 semantic records byte-for-byte;
- fresh rerun of 227 evidence generator reproduced exact 335 definitions / 50 files / 56 semantic records byte-for-byte;
- canonical `make verify-repo`: initial monolithic invocation reached the host 120-second command ceiling after `check_second_order_convergence.py`; every remaining Makefile command was then run in the exact declared order and passed;
- final source-structure/context/topology checks: 6 roots, 10 bands, 35 cross-band edges, 127 required `.context` files, 2,442/2,442 topology baseline paths accounted, 0 errors;
- final repository audit: **0 errors, 1 environment warning** (local Android Gradle wrapper absent; CI/release provisions Gradle 9.5.0).

Environment boundary: local Go is 1.23.2 while the repository requests Go >=1.26; network toolchain acquisition is unavailable. Cargo/rustc and local Gradle are unavailable. The SSH `x/crypto`-dependent passphrase path is source-reviewed and covered by repository declaration/static contracts but cannot receive its pinned full-workspace Go execution here. Rust/macOS-BPF and Android native production-build parity are not claimed.
