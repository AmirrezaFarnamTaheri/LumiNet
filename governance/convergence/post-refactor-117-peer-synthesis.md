# LumiNet post-refactor 117-donor peer synthesis

## Strongest current-wave convergence

### TUN/SOCKS association plane

Shadowsocks-libev, `tun2proxy`, and `tun2socks` independently reinforce that SOCKS setup is a protocol phase with explicit framing, lifetime, relay-address parsing, and association ownership. LumiNet keeps its existing mobile TUN/NAT owner and absorbs only the stronger invariants: complete control-frame writes, bounded setup, IPv4/domain/IPv6 UDP relay parsing, and single-winner association installation. The richer donor dual-stack payload stacks remain reference evidence because LumiNet's authoritative NAT implementation explicitly remains IPv4-only.

`tun2socks-python` contains an embedded Go implementation heavily overlapping the standalone `tun2socks` donor. The embedded implementation is revalidated but not credited as an independent semantic source; the Python bridge is assessed separately. Its vendored pybind11 tree is provenance/accountability evidence only.

### WebSocket/VLESS plane

The supplied Gorilla-derived/metacubex WebSocket repository, sing-box WebSocket/VLESS implementations, sing-cloudflared and dashboard framing behavior converge on a common result: a WebSocket-backed `net.Conn` must expose real deadline/address semantics, reads must be bounded, and protocol framing must be stateful rather than inferred independently on every message. LumiNet absorbs those invariants into its existing proxy and relay wrappers.

The supplied WebSocket donor identifies itself as `github.com/metacubex/websocket`; it is treated as source-compatible Gorilla-derived evidence, not falsely labeled as the exact target-pinned `gorilla/websocket` v1.5.3 bytes.

### Authority and security guardrails

The large sing-box fork exposes many additional server and camouflage mechanisms, including SSH/MTProxy/domain-fronting-style inbound authority. They are rejected because they create new externally reachable authority rather than harden an existing owner. The Android sing-box project contributes VPN lifecycle reference patterns, while Xposed hooks that conceal VPN/app state are rejected.

Water and water-rs independently demonstrate dynamically delivered WebAssembly Transport Modules. Their sandbox/configuration ideas are useful guardrail evidence, but arbitrary executable transport admission would create an untrusted-code runtime plane that LumiNet routing plugins do not currently possess. No WATM/WASM executable is promoted.

wsnet validates keeping vendor-specific networking behind a narrow integration boundary, but its firewall-whitelisting callbacks and patched curl/OpenSSL/ECH dependency bundle are not allowed to migrate into routing-plugin authority. Host-network mutation and native TLS/evasion dependencies remain target-owned.

### Evaluation/measurement evidence

Shadow contributes deterministic real-application network simulation methodology, not production syscall/runtime authority. The Tor Metrics website contributes reproducible aggregation/fixture methodology, not a current server/deployment stack. Vanguards contributes onion-service defense/verification knowledge without becoming a second Tor controller or implying onion-service hosting. uQUIC contributes fingerprint-sensitive QUIC evaluation knowledge while the target keeps its existing quic-go/transport owner.

## Shared-base and supersession truth

The two sing-box archives share 976 paths, 635 of them byte-identical at matching paths. Shared base behavior is not double-credited; only independently meaningful divergent mechanisms receive separate fine decisions. The 115 exact embedded `tun2socks-go` matches in the Python donor are similarly revalidated but semantically superseded by the standalone donor. These relationships are machine-readable in `post-refactor-117-overlap-provenance.csv`.
