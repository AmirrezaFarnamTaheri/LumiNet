# LumiNet post-refactor 137-donor peer-convergence release

## Outcome

This successor extends the frozen 117-donor release with 20 independently supplied repositories. The combined evidence graph contains **137 unique donors**, **35,743 file/link surfaces**, **6,258 directory records**, **4,456 bounded accountability groups**, **105,085 normalized donor-owned declarations**, and **4,740 adoption/accountability records**. Of those records, **284 are independently decidable semantic decisions**, including **69 current-wave decisions**.

The current wave contributes 9,187 validated outer archive members, 8,410 file/link surfaces, 777 exact archive directory members, 580 bounded groups, 32,073 declarations, two non-materialized symlinks, 69 fine decisions, and one independently inspected nested Gradle wrapper JAR containing 34 regular members. No current archive is byte-identical to a prior donor. 354 current surfaces duplicate bytes already present in the 117 corpus and are explicitly de-duplicated for semantic credit.

## Live target changes

Four target-native repair areas were justified by peer evidence:

1. **HTTP relay response identity:** an optional echoed response sequence must match the active serverless-relay request sequence; legacy omission remains compatible.
2. **DoH shared-work admission/lifetime:** unique-host shared lookups use a 32-slot fail-fast admission gate and a five-second shared lifetime detached from one waiter's cancellation.
3. **DoH response identity:** transaction ID and first DNS question must match the query before response records are accepted; compressed names are parsed with explicit pointer bounds/loop/traversal limits.
4. **DNS bypass boundary:** bypass rules match only an exact domain or dot-delimited subdomain; empty rules no longer match all names.

No donor becomes a second DNS server, relay runtime, proxy engine, TUN/NAT stack, firewall/host-network owner, Freenet/P2P node, executable WASM/plugin plane, or offensive packet/interception tool.

## Final dispositions

Freenet telemetry/core/Git, Exclave, Furious, go-tun2socks, GOST, fteproxy, Grasshopper, Hysteria Python and related projects are mined mechanism-by-mechanism for boundedness, lifecycle, packaging, verification, state or UX evidence. Large generated/vendor subtrees are surface-accounted without being promoted as target-owned semantics. GPL/AGPL/no-license peers do not contribute copied production source in this release.

`fsociety`, `hping` and `Intercept` offensive/spoofing/raw-packet/MITM capabilities are rejected completely as production authority and retained only as defensive/negative evidence. Broad root installers, mutable-master update paths, arbitrary remote proxy collection, second proxy/server/firewall authorities, opaque executable WASM and bundled/generated runtimes are final rejection/guardrail decisions rather than queued work.

## Validation boundary

The changed Go seams passed 100 race-enabled repetitions plus `go vet` in exact-source dependency-isolated harnesses. The strict combined ledger passes the convergence skill validator at 4,740 records / 268 unique tests or decision anchors / 0 warnings, and all 8,410 current donor file/link surfaces independently match extracted bytes or captured link-target hashes.

Full repository/toolchain and immutable artifact verification is recorded by the external release receipt after freezing the source. Local Go is 1.23.2 versus the declared Go 1.26.x/toolchain 1.26.5; Rust/Cargo/Miri are unavailable and the local Android wrapper is absent. No unavailable execution path is represented as passing.

## Repository gate status

The monolithic canonical repository gate is intentionally not collapsed into a false pass: it timed out after the 97-donor successor gate had passed, while the 117 gate was starting. The exact remaining Makefile tail was executed separately. A task-created Python bytecode cache was detected by repository audit, removed, and the affected gates rerun cleanly. The final repository audit has `errors=0` and only the inherited missing-local-Android-wrapper warning.
