# Post-refactor-225 omission and contradiction audit

## Mechanical coverage

- current wave: 23 donors, 1,871 ZIP members, 1,548 files, zero symlinks;
- current donor directory/subdirectory accountability: 323 nodes;
- current extracted definitions: 7,255;
- current semantic records: 1,133;
- high-signal files: 992;
- high-signal files without repository+module+file focused decisions: **0**;
- all-history overlay: 38 donors, 2,461 surfaces, 9,511 definitions, 202 subtree groups;
- all-history high-signal surfaces: 1,572;
- all-history UI/product surfaces: 159;
- immutable 224 denominators preserved: 913 surfaces, 2,256 symbols, 72 semantic records.

Every non-reference current-wave semantic record has a unique acceptance anchor. Reference-only records use `n/a` rather than pretending shared smoke checks prove behavior. Donor ZIP bytes, extracted files, surface hashes, directory Merkle hashes, symbol-source hashes, semantic backlinks, target paths and parent/dependency graphs are checked by `check_post_refactor_225_convergence.py`.

## File/subfolder/symbol audit

The audit explicitly distinguishes repository records, module/subtree records and high-signal file records. Large repositories such as v2rayNG, WireGuard-Go, uTLS, SNI-Spoofing-Go and UptimeFlare were split by subsystem so unrelated UI, device, crypto, deployment and test surfaces do not inherit one donor-wide disposition. Extracted definitions inherit the focused source-file decision and are independently hash-linked back to the surface matrix.

## Product/UI audit

The product-specific pass reopened both 225 and inherited 224 peers. Donor UI/product surfaces were compared against current target pages and yielded natural placements in DNS, Connections, Rules, Settings/WARP, Health, Logs and Profiles. Operations remains a read-only lab for advanced planners. No product widget directly mutates queues, installs rules, activates scanned endpoints, downloads routing artifacts, or bypasses the authenticated configuration owner.

## Contradictions found and resolved

- strict TLS security model vs historical insecure scanners: zero-consumer insecure facades retired; measurement and trusted qualification separated;
- structured SNI parser vs malformed old TLS compatibility fixture: fixture repaired to a real ClientHello rather than weakening parsing;
- new diagnostics helper `b` vs existing package test helper: 225 helper renamed, restoring four-platform declaration integrity;
- Wave-24 byte equivalence vs intentional 225 TLS-fragment hardening: frozen pre-225 owner is anchored and the descendant transform is explicitly accounted by the 225 delta;
- historical 224 delta vs live 225 source: 224 checker now uses the frozen pre-225 successor inventory for delta reconstruction;
- fake SNI repeat UI dimension vs actual behavior: fake dimension pruned; product copy states raw fake-packet repetition is not implemented;
- keyless `warp://` parsing vs WireGuard identity truth: fabricated key material removed; missing keys fail closed;
- covert TUIC label vs raw TCP implementation: false transport fails closed while normal TUIC/QUIC remains.

## Reference-heavy donor rechecks

WireGuard-Go, Wormhole and TT were explicitly reopened because their first mechanical ledger version was too reference-heavy. WireGuard now contributes peer/readiness/session lifecycle policy; Wormhole contributes bounded declarative workflow lifecycle; TT is explicitly superseded by the existing TUI stack. uTLS/TUIC/Wintun and v2rayNG module clusters were likewise split by actual responsibility instead of inheriting donor-wide labels.

## Remaining uncertainty

No unresolved high-signal surface or orphan semantic record is known. Runtime/native equivalence is not claimed where this environment cannot execute the required toolchain or OS driver. Full repository Go 1.26.5 builds, Rust/Cargo builds, Android Gradle wrapper builds, driver-backed Wintun behavior and external-network/service behavior remain separate from the source-level and isolated-package verification performed here.
