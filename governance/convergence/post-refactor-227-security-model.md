# Post-refactor-227 security model

## Authority boundary

Peer packet/TLS code is not automatically executable authority. Post-refactor-227 preserves existing runtime, raw-packet, update, profile, and core-manager owners.

## Flow identity and lifetime

Captured SYN evidence is bound to source IP, source port, destination IP, and destination port. Entries expire after 30 seconds, are capped at 4,096, and out-of-window injection consumes the matching observation once. This closes port-only collision, stale evidence, and accidental cross-flow reuse.

## Fail-closed sequence behavior

Wrong-sequence/out-of-window injection no longer fabricates a `1000/1` sequence when authoritative SYN evidence is absent. It fails before injection. The older TTL-limited decoy mode keeps its separate historical semantics and is not mislabeled as donor-equivalent wrong-sequence spoofing.

## TLS decoy bounds

The canonical builder accepts only bounded ASCII DNS SNI, maximum 219 bytes, checks entropy reads, and produces exactly 517 bytes with an explicit padding extension. Diagnostic and live Go paths cannot drift to separate decoy templates.

## Handshake planner

The planner requires coherent SYN/SYN-ACK/third-ACK evidence, treats RST as failure, and does not mark relay-ready after fake injection until server ACK evidence still acknowledges the real `ISN+1` sequence. It performs no network I/O and grants no raw-packet authority.

## Rejected authority expansion

Mutable “latest” binary downloads, peer Xray installation/runtime, bundled release binaries, and peer UI-driven installation are excluded from update/runtime authority. macOS BPF support is not claimed without target-native Darwin validation.
