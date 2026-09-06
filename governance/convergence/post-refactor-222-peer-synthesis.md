# Post-refactor-222 peer synthesis

This document is the human-readable projection of `post-refactor-222-adoption-ledger.csv`. The ledger, surface matrix, symbol matrix and archive accountability remain the machine-readable sources of truth.

## Synthesis rules

- Preserve one LumiNet authority owner per consequential state or side-effect domain.
- Extract independently useful primitives and product affordances; do not copy donor-shaped runtimes merely to increase feature count.
- Reuse historical convergence evidence by exact content identity only; changed/unmatched material is reopened.
- Treat rejected, superseded, negative and non-code evidence as first-class value when it yields a guardrail, oracle, constraint or product insight.
- Archive symlinks are explicit surfaces. They were validated as links and never followed during extraction.

## Current donor corpus

| Donor | Records | Dispositions | Strongest current-pass value / resolution |
|---|---:|---|---|
| `Aether-GUI-main(1).zip` | 1 | reference-only×1 | Aether GUI exact-byte historical revalidation |
| `Aether-main(1).zip` | 2 | reference-only×2 | Aether exact-byte historical revalidation; Aether archive symlink aliases |
| `Captcha_hacking-master.zip` | 2 | reference-only×1, rejected-with-reason×1 | CAPTCHA solver/training pipeline |
| `DNS-Persist-master(1).zip` | 1 | reference-only×1 | DNS-Persist exact-byte historical revalidation |
| `Deanonymizing-quietly-all-of-Tor-main.zip` | 1 | guardrail-derived×1 | Tor deanonymization/correlation research claim |
| `EDtunnel-main.zip` | 5 | adapted×1, guardrail-derived×1, recomposed×1, reference-only×1, superseded×1 | remembered proxy success and bounded fallback; multi-proxy rotation/fallback diversity; Cloudflare Worker VLESS/Trojan/SOCKS/UDP runtime; path/query proxy and credential overrides |
| `HackingDetectingSystemOfUnauthorizedLoginDevices-master.zip` | 5 | guardrail-derived×1, reference-only×2, rejected-with-reason×1, superseded×1 | new-IP/device/browser/OS/time/impossible-travel/VPN/bot risk signals; password/OAuth/OTP/reset/email account authority; failed-login lockout/brute-force controls |
| `Kloak_platform-master(1).zip` | 7 | guardrail-derived×2, reference-only×3, rejected-with-reason×1, superseded×1 | custom PBKDF2/OpenPGP/browser crypto; plain JSON configuration persistence carrying identity/connection material; localhost-only URL validation gap; browser workers/download queues |
| `Marz-main.zip` | 2 | adapted×1, reference-only×1 | one-tap subscription deep-link proposal |
| `Marzban-node-master.zip` | 5 | guardrail-derived×1, reference-only×1, superseded×3 | client-certificate node API admission; Xray process lifecycle callbacks and capped log deque; inbound allow-list and API route filtering; self-signed long-lived certificate / optional-insecure RPyC fallback |
| `Nabzram-master.zip` | 6 | adapted×2, reference-only×2, superseded×2 | pause live-log tail when operator scrolls; theme preference/context; Xray process/subscription/TinyDB desktop backend; desktop update-check/download workflow |
| `TaoConnect-main.zip` | 5 | recomposed×1, reference-only×2, rejected-with-reason×1, superseded×1 | dark/theme preference; lease expiry and profile-validity awareness; timer-only browser expiration notifications |
| `VpnDad-main.zip` | 6 | adapted×1, hardened×1, reference-only×2, superseded×2 | health verdict and bounded timeline; shareable diagnostic bundle with secret minimization; Keychain/profile repository and secret-minimized export; iOS PacketTunnel/engine bridge lifecycle |
| `ZedPass-main(1).zip` | 1 | reference-only×1 | ZedPass exact-byte historical revalidation |
| `bittorrent-nodeid-master.zip` | 1 | extracted×1 | BEP42 IPv4 node-ID binding |
| `cdin-main.zip` | 6 | adapted×2, extracted×1, reference-only×2, rejected-with-reason×1 | keyboard command palette; deterministic fuzzy subsequence ranking; bounded command history / recent destinations; editor filesystem/terminal/plugin authority |
| `coredns-master(1).zip` | 2 | reference-only×2 | CoreDNS exact-byte historical revalidation; CoreDNS repository-administration symlink aliases |
| `defyxVPN-main.zip` | 1 | reference-only×1 | defyxVPN exact-byte historical revalidation |
| `dns-over-https-proxy-master(1).zip` | 2 | reference-only×2 | DNS-over-HTTPS proxy exact-byte historical revalidation; DoH proxy vendor-source symlink alias |
| `goida-vpn-configs-main.zip` | 1 | reference-only×1 | goida VPN configuration corpus exact-byte historical revalidation |
| `mission-improbable-master.zip` | 6 | adapted×1, guardrail-derived×2, hardened×1, reference-only×1, rejected-with-reason×1 | downloaded release/signature verification before install; durable signed-artifact publication; explicit signing-key ownership and immutable release inputs; root/ADB/fastboot flashing, signature spoofing and OS image mutation; bundled signing/verity JARs and helper binaries |
| `stealthspanner-master(1).zip` | 4 | extracted×1, rejected-with-reason×2, superseded×1 | latency jitter and packet-loss evidence; automatic provider VPN-config download; subjective country privacy score; broad UFW reset kill switch and home-directory VPN credentials |
| `torrent-live-master(1).zip` | 6 | adapted×1, guardrail-derived×1, inspired-native×1, recomposed×1, reference-only×1, rejected-with-reason×1 | bounded peer candidate admission and duplicate evidence; local IPv4 range deny policy; same-IP/different-port observation without NAT false positives; active fake-infohash/findspies peer probing; torrent streaming/storage/freerider runtime |

## Target-native composition results

### Peer discovery admission and planning
`bittorrent-nodeid` contributes BEP42 IPv4 identity binding. `torrent-live` contributes bounded candidate/blocklist/shared-address evidence, but its active probing and content runtime are not imported. LumiNet recomposes the safe semantics into a read-only planner: public IPv4 admission, bounded local CIDR deny policy, duplicate/self rejection, BEP42 validation, exact XOR ordering, descriptive trust, NAT-safe shared-address evidence and bounded output. It performs no discovery, DNSBL lookup, dialing, routing, persistence or trust mutation.

### Endpoint continuity and quality evidence
EDtunnel contributes remembered-success/fallback concepts; stealthspanner contributes jitter/loss evidence. LumiNet keeps its existing eligibility/quota/success/latency authority, adds jitter/loss only as penalties, and permits continuity/diversification only inside a five-point quality band. Deterministic scope hashing replaces random rotation.

### Operator product plane
cdin contributes command-search ergonomics and fuzzy ranking concepts; Nabzram contributes live-tail behavior and appearance handling; TaoConnect reinforces appearance persistence/expiry presentation; VpnDad contributes health/diagnostic composition. LumiNet unifies these into one canonical navigation registry, accessible command palette, local System/Light/Dark preference, operator-controlled live-tail, and a read-only Health workspace with allow-listed redacted export.

### Update and mutation reliability
mission-improbable contributes verification-before-publication and release-integrity lessons. LumiNet hardens its existing signed-update admission with synchronized staged content, regular-target confinement, atomic Unix rename-overwrite and parent-directory sync. The shallow 221 Rust retry helper is removed: configuration CAS retry remains in `foundation/config.Manager.Mutate`, while remote side effects remain in `foundation/remoteaction.Executor` with reconciliation.

### Defensive and negative evidence
The CAPTCHA solver, Tor deanonymization research, unauthorized-login heuristics, Kloak weak crypto/config/URL checks, Marzban insecure fallback, stealthspanner country scoring/firewall reset, EDtunnel query/path authority, torrent active probing and mission device-flashing surfaces are not converted into operational donor capabilities. Their useful value becomes explicit claim limits, security boundaries, admission constraints, or tests.

## Historical revalidation

Exact regular-file content for Aether GUI, Aether, CoreDNS, defyxVPN, DNS-over-HTTPS proxy, DNS-Persist, goida VPN configs and ZedPass is bridged to the earlier fine-grained convergence corpus rather than duplicated. Partial historical matches in cdin, Kloak, Nabzram, TaoConnect, torrent-live and VpnDad are retained only for the exact matching files; unmatched/current surfaces receive post-222 dispositions. Archive symlinks are excluded from exact-byte historical counts and receive their own records.

## Composition conclusion

The resulting product is intentionally a semantic superset rather than a directory union. Where donor behavior is stronger and separable it is extracted or adapted; where LumiNet already has a stronger owner, the donor is superseded; where a peer would introduce duplicated authority, unsafe execution, weak secrecy or unrelated product scope, the peer remains evidence/guardrail/reference rather than executable product code.
