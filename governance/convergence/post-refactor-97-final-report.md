# LumiNet post-refactor 97-donor final convergence report

## Outcome

The frozen 83-donor release has been extended with the 14 newly supplied Tor-related archives. Because the earlier 20-donor wave was already included in the 83 total, the evidence-backed successor total is **97 unique donor repositories** (63 + 20 + 14).

The combined graph accounts for 20,585 file/link surfaces, 2,701 bounded module/accountability groups, 39,419 normalized declarations, 2,856 adoption/accountability records, and 155 fine semantic decisions. The new Tor wave contributes 14,444 archive members, 12,010 surfaces, 2,434 directory records, 2,077 groups, 19,675 donor-owned declarations, 24 non-materialized symlink surfaces, and seven independently inspected nested archives containing 153 members.

## Live target changes

1. Tor runtime startup no longer succeeds on a 300 ms liveness inference. It requires authenticated control bootstrap progress 100 inside a bounded startup window and tears down on exit/timeout.
2. Tor control now has one framed, bounded, deadline-aware parser for multiline/data replies and asynchronous events, with pre-write rejection of CR/LF/NUL command injection.
3. Tor control authorization uses exact full-line whitelist matching, closing safe-prefix/trailing-argument authorization.
4. TorProcess delegates bootstrap and ownership semantics to the same deep controller.
5. A successor correction layer closes all identified historical future/deferred wording and corrects the earlier SOCKS-auth-isolation implication without mutating frozen evidence.

## Non-adoptions

Second firewall/TUN authorities, root-mutating installers, LD_PRELOAD interception, duplicate userspace TCP stacks, onion-service server/Kubernetes ownership, external Onionoo service deployment, arbitrary daemon restart loops, and donor-bundled native Tor binaries were rejected or retained strictly as reference/guardrail evidence. Research path-selection and measurement systems remain observational.

## Verification boundary

Changed Go seams passed 100 race-enabled repetitions plus go vet in exact-source harnesses. Repository/source/evidence gates and release-byte verification are recorded separately. The host cannot execute the declared Go 1.26 workspace, Rust/Cargo/Miri, or the absent local Android wrapper, so those results are not claimed.
