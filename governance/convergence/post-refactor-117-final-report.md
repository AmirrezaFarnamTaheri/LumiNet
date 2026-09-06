# LumiNet post-refactor 117-donor peer-convergence release

## Outcome

This successor extends the frozen 97-donor release with 20 independently supplied repositories. The combined evidence graph contains **117 unique donors** across four preserved waves (63 historical + 20 prior post-refactor + 14 Tor-focused + 20 current), **27,333 file/link surfaces**, **5,481 directory records**, **3,876 bounded surface-accountability groups**, **73,012 normalized donor-owned declarations**, and **4,091 adoption/accountability records**. Of those records, **215 are independently decidable semantic decisions**, including **60 current-wave decisions**.

The current 20-donor wave contributes 8,097 validated outer archive members, 6,748 file/link surfaces, 1,349 directories, 1,175 bounded groups, 33,593 normalized declarations, six non-materialized symlinks, and one independently inspected nested Gradle wrapper JAR containing 33 regular members. No new archive is byte-identical to a prior donor. Shared-base overlap is separately dispositioned so it is not double-credited. All release accountability groups are capped at 100 surfaces.

## Live target changes

Three target-native repair slices were justified by cross-peer evidence:

1. **Mobile TUN/SOCKS setup:** association setup is bounded by context/deadline, control frames use complete writes, UDP ASSOC replies accept IPv4/domain/IPv6 relay endpoints, and concurrent first packets install exactly one association while closing losers. This does **not** change the authoritative NAT plane's explicit IPv4-only payload support.
2. **VLESS/WebSocket state:** the response preface is consumed exactly once, supports fragmentation across WebSocket messages without recursive reads, validates the response version, and shares a 1 MiB WebSocket message bound plus real address/deadline behavior.
3. **Relay WebSocket `net.Conn`:** the wrapper exposes underlying local/remote addresses, applies real combined deadlines, enforces a 1 MiB read limit, and bounds the initial application-level relay confirmation before clearing the setup deadline.

No peer repository becomes a second proxy engine, firewall authority, DNS owner, Tor controller, inbound server plane, TUN/NAT stack, executable plugin plane, or native TLS/QUIC dependency owner.

## Final dispositions

The sing-box repositories, Shadowsocks-libev, wsnet, WGSocks and other GPL donors are used only as independently rederived mechanism/reference/negative evidence; no GPL source is copied into LumiNet. `tun2proxy`, `tun2socks`, the WebSocket donor, uQUIC, Vanguards, Shadow and Water-family repositories are also dispositioned mechanism-by-mechanism rather than imported wholesale.

Dynamic WATM/WASM transport execution, Xposed VPN/app concealment, remotely managed cloud-tunnel inbound authority, additional SSH/MTProxy/domain-fronting servers, second firewall mutation paths, broad root-mutating installers, and donor prebuilt executables are final rejections/guardrails for this release rather than queued work.

## Validation boundary

The final changed Go seams are exercised in dependency-isolated exact-source harnesses because this host provides Go 1.23.2 while LumiNet declares Go 1.26.x and cannot fetch the newer toolchain/dependencies. Each changed seam passed 100 race-enabled repetitions plus `go vet` at the frozen implementation state. The existing secure-DNS TUN test is an inherited intermittent Go-1.23 harness flake reproduced in the frozen 97 baseline; it is not used as evidence for the current repairs and is not relabeled as passing.

Rust/Cargo/Miri remain unavailable and the local Android Gradle wrapper is absent. No unexecuted full-workspace Go 1.26, Rust/Miri, or Android result is represented as verified. Repository/evidence/release-byte gates are recorded separately in the final external release receipt.

The current-wave ledger passes the convergence skill validator directly at 1,235 records, 60 unique tests/decision anchors, and zero warnings. Frozen historical rows contain older evidence-pointer conventions, so the canonical historical ledgers remain immutable while a 74-row successor normalization overlay supplies current-schema pointers. The resulting strict combined ledger passes at 4,091 records, 199 unique tests/anchors, and zero warnings; the overlay changes evidence addressing only, not historical dispositions or donor/source hashes.

The canonical repository verification passed through eighth-order convergence before the host execution ceiling. The exact remaining Makefile tail then passed command-for-command; this timeout/tail distinction is preserved rather than collapsing the monolithic invocation into a false pass. Repository audit ends at `errors=0` with only the inherited local-Android-wrapper warning.
