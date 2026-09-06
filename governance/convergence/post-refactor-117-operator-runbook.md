# LumiNet post-refactor 117-donor operator and migration runbook

## SOCKS/TUN behavior

SOCKS TCP and UDP-association negotiation now has a bounded setup deadline. After successful TCP SOCKS negotiation the deadline is cleared before data relay. UDP association creation also honors the adapter context; concurrent first packets for the same client source converge on one installed association and close redundant candidates.

A SOCKS server may return an IPv4, domain-name, or IPv6 **relay endpoint**. LumiNet selects an IPv4/IPv6 local UDP socket accordingly. This does not change the packet/NAT capability: the authoritative NAT owner remains IPv4-only, so operators must not advertise general IPv6 tunneled-payload support from this change.

## WebSocket/VLESS behavior

Production proxy WebSockets use a 1 MiB read limit and expose actual underlying connection addresses/deadlines. VLESS response metadata is a one-time connection preface. It may be fragmented across multiple WebSocket messages; once consumed, later payload beginning with `0x00` is preserved as application data. A malformed nonzero response version fails closed.

The relay WebSocket wrapper similarly exposes real `net.Conn` semantics and a 1 MiB read limit. The initial relay `connected` confirmation is bounded by the caller deadline or five seconds, whichever is earlier; the setup deadline is cleared after successful confirmation.

## Authority guardrails

Do not install donor root-mutating scripts, import GPL proxy engines, activate peer inbound SSH/MTProxy/domain-fronting servers, execute Water/WATM modules, apply Xposed VPN-concealment hooks, allow routing plugins to mutate firewall whitelists, or replace the pinned QUIC/TLS stacks merely because peer implementations expose those capabilities. These are final negative/guardrail decisions in this release.

## Validation boundary

Use the exact source/release receipt for validation status. On the current host, changed Go seams are proven through isolated exact-source harnesses under the race detector (100 repetitions) and `go vet`; the full Go 1.26 workspace cannot be fetched/executed. The existing secure-DNS TUN test is a known inherited intermittent Go-1.23 harness flake and is not a current repair oracle.
