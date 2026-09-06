# Post-refactor-226 omission and contradiction audit

## Denominators

- donor archives: 14/14;
- ZIP members: 1,557/1,557;
- donor files: 1,299/1,299;
- donor subdirectories: 244, plus 14 donor-root Merkle records;
- extracted definitions: 15,975/15,975;
- focused module records: 134;
- focused high-signal file records: 745/745;
- high-signal files without focused disposition: 0;
- semantic records: 893;
- all-history donors: 52;
- all-history surfaces: 3,760;
- all-history definitions: 25,486;
- all-history module/subtree groups: 284;
- all-history high-signal surfaces: 2,317;
- all-history UI/product surfaces: 161.

## Audit ladder

1. **Archive safety — closed.** Original archives are path/case/duplicate/type/CRC checked and extracted bytes are rehashed.
2. **Files — closed.** Every current-wave regular-file surface has path, size, SHA-256, classification, authority status and semantic backlinks.
3. **Directories — closed.** Every donor directory and root has deterministic Merkle accountability.
4. **Definitions — closed for the documented extractor.** The 15,975 denominator combines the legacy definition policy with Rust top-level const/static/macros, SRSC package registration variables and conservative structural C++ definitions.
5. **Modules — closed.** Large Shadowsocks, SSH and subconverter trees are split by focused module/file records rather than donor-wide labels.
6. **High-signal leaves — closed.** All 745 implementation/test/configuration/script/deployment/UI surfaces have focused records.
7. **State/recovery — closed for promoted behavior.** Revision transactions, browser handoff state, worker recovery, WebSocket readiness, gateway DAG rollback and WireGuard mapping expiry have explicit allowed/forbidden semantics.
8. **Trust/negative paths — closed for identified risks.** Unsupported protocol fallback, invalid SS2022 keys, empty SSH auth, SOCKS length/type overflow, non-loopback browser targets, credential-bearing Tailnet authority, unbounded process recovery, false WebSocket readiness, cyclic gateway graphs and non-expiring receiver-index mappings are rejected.
9. **Product/operator surfaces — closed.** New planning value is present in Rules, Settings, Health, Connections and Operations; UI remains non-authoritative.
10. **Historical overlay — closed.** 224/225 semantics remain immutable and 226 appends a 52-donor overlay.
11. **Target delta — closed.** Every add/modify/delete relative to the exact frozen 3,018-file 225 inventory is mechanically regenerated.
12. **Canonical verification — closed for executable repository checkers.** Historical/current convergence, topology, reachability, route/platform/native truth, ABI/FFI, peer convergence and repository audit pass under the recorded environment.

## Contradictions resolved

- local duplicate Shadowsocks implementations vs external core authority -> duplicate zero-consumer owners retired;
- unsupported protocol fallback vs fail-closed protocol identity -> explicit SOCKS/HTTP branches plus unsupported errors;
- SS2022 textual key acceptance vs method-specific binary key size -> exact decoded component bounds;
- SSH dial path vs empty/invalid auth -> pre-network auth admission;
- SOCKS one-byte/u16 fields vs unchecked input width -> validate before serialization;
- TCP-open checks vs WebSocket application readiness -> require complete 101/Upgrade/Connection/Accept/TLS evidence;
- deployment donor scripts vs target authority -> recomposed DAG planning only;
- MWGP obfuscation vs WireGuard security claims -> obfuscation remains traffic-shape-only;
- historical peer checker vs intentional 226 deletion -> frozen 225->226 retirement receipt validates the successor without restoring dead code.

## Remaining uncertainty

No unresolved current-wave high-signal surface is known. Toolchain-unavailable native/runtime claims remain explicitly outside executed evidence: full Go 1.26.5 workspace tests, Cargo/rustfmt-backed Rust builds/tests, local Android Gradle-wrapper builds, and full frontend semantic typechecking with installed dependency types.
