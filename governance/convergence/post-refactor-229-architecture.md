# Post-refactor-229 architecture

229 evaluates five outer donor archives against the immutable 228 target and separately admits the nested MITM source archive carried by `my-relay-assets`. The outer corpus contains 7,531 regular files, 3 symlinks, 2,261 root/directory Merkle records, and 30,602 indexed definitions. The nested MITM layer contributes 1,477 files, 1,268 directory/root Merkle records, and 242 definitions without inflating the outer donor denominator.

Existing authority boundaries remain singular: `host_network.go` owns host DNS/proxy/TUN mutation; `endpoint_pool_plan.go` owns endpoint scoring/quota admission; `profile_service.go` owns subscription refresh lifetime; relayclient owns the serverless relay wire; signed-update verifier/store own update admission/replay state. 229 adds bounded planning/evidence surfaces and surgical hardening rather than donor-shaped runtimes.

## Composition

- Hiddify: client/config UX, per-app intent, profile/rule workflows, recovery affordances and negative update evidence.
- ProxyCloud: small selection/workflow evidence; early-exit ranking bias rejected.
- Mullvad: deep fail-closed tunnel/firewall/split-tunnel/relay/update state-machine evidence.
- my-relay-assets: artifact provenance/type-mismatch guardrails plus a separately admitted historical MITM source corpus.
- MasterHttpRelayVPN-RUST: quota headroom, relay sequencing/diagnostics, leak-guard detail, fronting/tunnel/runtime lessons, and mobile/deployment evidence.

No donor daemon, VPN runtime, firewall, TUN driver, CA/MITM engine, tunnel-node service, mutable remote corpus, browser/mobile host, or opaque packaged binary becomes a parallel target authority.
