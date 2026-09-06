# LumiNet post-refactor 137-donor operator and migration runbook

## Serverless HTTP relay

The existing serverless HTTP relay continues to send request sequence values. When a relay response includes `Seq`, it must equal the current request sequence; otherwise the operation fails closed and preserves existing sequence rollback behavior. Responses that omit the optional sequence remain compatible with older relay implementations.

## DoH behavior

Shared DoH work is no longer owned by the cancellation of the first singleflight waiter. Each shared lookup has its own five-second maximum lifetime and must obtain one of 32 admission slots; a unique-host burst beyond that bound fails fast rather than spawning unbounded work. Individual callers may still cancel their own wait without cancelling shared work needed by remaining waiters.

Before accepting A-record data, the DoH response must match the request transaction ID and first question (qname/qtype/qclass). DNS compression pointers are bounds-checked, loops are rejected, and parsing stops after a fixed traversal ceiling. This is response mix-up protection, not DNSSEC authentication.

## WhiteDNS bypass policy

Bypass rules are normalized for case, whitespace and a trailing dot. Empty rules are ignored. A rule matches only the exact domain or a dot-delimited subdomain; `example.com` does not match `badexample.com` or `example.com.evil`.

## Authority guardrails

Do not import current-wave proxy engines, TUN stacks, Freenet node/runtime, arbitrary executable WASM, offensive raw-packet/MITM tooling, donor firewall/root installers, mutable-master updaters, scraped proxy feeds, generated Frozenlib runtimes, or bundled upstream binaries merely because they appear in peer projects. Existing LumiNet DNS, relay, proxy, TUN/NAT, host-network, extension and release owners remain authoritative.

## Validation boundary

Changed Go seams are validated in dependency-isolated exact-source harnesses under the Go race detector for 100 repetitions plus `go vet`. Full-workspace Go 1.26, Rust/Miri and Android execution remain unavailable on this host. Use the final release receipt for exact repository-gate and artifact-byte evidence.
