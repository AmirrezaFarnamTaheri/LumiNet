# LumiNet post-refactor 97-donor omission and contradiction audit

## Corpus closure

The accounted corpus is 63 historical donors + 20 prior post-refactor donors + 14 new Tor donors = **97 unique donors**. Across the combined evidence graph there are **20,585 file/link surfaces**, **2,701 bounded module/accountability groups**, **39,419 normalized declarations**, and **2,856 adoption/accountability records**, of which **155 are fine semantic decisions**.

For the 14 new archives specifically, all 14,444 outer members were validated before extraction. The inventory contains 11,986 regular files and 24 symlink surfaces (12,010 total file/link surfaces) plus 2,434 directory records. Symlinks were recorded and hashed/target-accounted but not materialized during safe extraction. Seven nested archives were independently inspected: 153 members total, zero unsafe nested paths/types/collisions.

The tor-controller vendor tree is intentionally not a blind spot: 10,337 vendored files are individually SHA-256-accounted. Their declarations are excluded from donor-owned symbol totals so dependency internals cannot masquerade as tor-controller semantics.

## Omission ladder

- Files/symlinks: complete combined surface matrix; no unlinked new implementation/config/script/deployment/product surface.
- Roots/packages/deliverables: all 14 archive roots, all bounded module groups, manifests, tests, examples, build/deploy surfaces, and nested archives dispositioned.
- Symbols/contracts: normalized donor-owned declarations scanned; semantic records split where behavior has independent authority/risk/disposition.
- State/recovery: Tor spawn -> authenticated control -> bootstrap progress 100 -> ready is now explicit; exit/timeout tears down.
- Negative paths: CR/LF/NUL command injection, oversized replies, command deadline expiry, malformed framing, asynchronous event interleaving, never-bootstrapping live child, and safe-prefix-plus-trailing-argument authorization have focused tests.
- Operator/deployment: startup readiness is no longer a fixed 300 ms liveness inference; a bounded 60 s startup window is the new contract.
- Historical claims: 11 resolution rows remove identified deferred/future ambiguity without rewriting frozen evidence.

## Contradictions resolved

No production DNS tunnel is claimed. No active SOCKS-auth isolation is claimed. No research/simulation donor is treated as traffic-capture or path-selection authority. Onion-service server mechanisms are not imported into a client/runtime role. Host-network mutations remain behind the target's single privileged owner rather than donor iptables scripts.

## Residual environment boundaries

Local Go is 1.23.2 while the repository declares Go 1.26.x; Rust/Cargo/Miri are unavailable; the local Android Gradle wrapper is absent. These are validation-environment limits, not open donor-convergence tasks. No unexecuted full-workspace Go 1.26, Rust/Miri, or Android result is labeled passing.
