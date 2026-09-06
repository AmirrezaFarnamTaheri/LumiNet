# Post-refactor-227 validation

## Verified evidence/accountability

The dedicated post-refactor-227 checker reopens the original donor ZIP, validates paths/CRC/member types, compares all 50 extracted file bytes, rehashes 10 directory Merkle records, validates 335 symbol backlinks, checks all 56 semantic records and focused high-signal links, preserves the 53-donor historical overlay, and verifies the exact 226->227 source delta.

## Executed behavior/product evidence

- Exact-source Go proxy registry harness: PASS (four-tuple identity, TTL, one-shot consume, IPv4/IPv6 SYN parsing, bounded capacity).
- Exact-source Go diagnostics/tlsdecoy/handshake harness: PASS (517-byte ClientHello, SNI/padding bounds, handshake evidence state machine).
- Full dependency-free Control UI characterization chain: **444 assertions PASS**, including **54 post-refactor-227 checks**.
- Modified TypeScript/TSX transpile parse using global TypeScript **5.8.3**: 0 diagnostics.
- Full frontend project typecheck: environment-blocked because `vite/client` and `node` type packages are intentionally absent from the clean source tree.

## Canonical repository verification

The canonical Makefile sequence was executed in order. The monolithic invocation stopped at the third-wave historical contract after the SNI validator was deliberately moved to the lower `networking/tlsdecoy` owner; that checker was updated to accept either the historical local validator or the successor single owner while preserving the 219-byte invariant. The remaining untouched commands were executed in bounded bands. All historical convergence gates through post-refactor-226, current post-refactor-227, route/platform/native ownership, ABI/FFI static gates, 22 native verification-coverage checks, five LumiCore link tests, global/peer convergence, and repository audit pass.

Repository audit: **0 errors, 1 environment warning** for the absent local Android Gradle wrapper; CI/release provisions Gradle 9.5.0.

## Claim boundary

The repository requires a newer Go toolchain than the local Go 1.23.2 for full workspace tests; exact-source compatible Go harnesses are executed instead. Cargo/rustc are unavailable, so Rust changes are statically validated and independently structure-checked, not runtime-verified. Darwin BPF integration is not claimed. No unavailable validation is represented as passing.
