# Post-refactor-227 peer synthesis

## Donor denominator

The new wave contains 1 donor, 60 ZIP members, 50 files, 9 subdirectories, 10 directory Merkle records including root, 335 extracted Rust definitions, 12 focused module decisions, 43 focused high-signal file decisions, and 56 semantic records.

## Valuable mechanisms absorbed

- Full four-tuple connection identity and explicit registration/deregistration lifetime exposed weakness in the target port-only SYN registry.
- The donor’s padded 517-byte TLS ClientHello became a protocol oracle for a single target-native Go builder and a corrected Rust mirror.
- The donor SYN/SYN-ACK/third-ACK/fake/server-ACK/RST lifecycle became a read-only target planner with stricter third-ACK coherence.
- Donor scanner behavior is retained as an oracle; the existing LumiNet scanner remains more bounded and authoritative.

## Explicit non-adoptions

- macOS BPF: reference-only until target-native Darwin runtime validation is available;
- Xray parser/runtime: superseded by canonical profiles/core manager;
- mutable Xray/WinTun/latest downloads: rejected as update-authority bypass;
- bundled release binaries: derived evidence, never source of truth;
- 643-unique peer SNI corpus: reference-only; the existing curated 285-candidate target corpus is deliberately unchanged.

## Second-order convergence

The most important result is consolidation, not feature count. Diagnostics and the live Go tunnel now share `networking/tlsdecoy`. Sequence evidence is bounded, exact-flow, and one-shot. The full donor relay-confirmation lifecycle is not falsely claimed in the live runtime; it remains an explainable planner until capture authority can observe and validate the full exchange.
