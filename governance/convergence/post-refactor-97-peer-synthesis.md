# LumiNet post-refactor 97-donor peer synthesis

## Decision

The 83-donor baseline already included the prior 20-donor wave (63 historical + 20 post-refactor). The 14 newly supplied Tor-related archives therefore produce **97 unique donors**, not 103 or 117. No donor is double-counted to satisfy a headline number.

The 14-donor wave adds 14,444 archive members, 12,010 file/link surfaces, 2,434 directory records, 2,077 bounded module groups, 19,675 donor-owned normalized declarations, 24 explicitly recorded symlinks, and seven nested archives containing 153 members. Vendored dependencies remain hash-accounted but are not credited as donor-owned semantics; this matters most for tor-controller, whose 10,337 vendored files are fully inventoried while only donor-owned declarations contribute to semantic symbol counts.

## Adopted/hardened convergence

Three peer mechanisms beat the existing target behavior strongly enough to change live ownership now. TOPL and tor-android independently require control/bootstrap readiness before declaring Tor usable, so runtime startup now waits for authenticated bootstrap progress 100 under a bounded startup deadline. txtorcon and TOPL provide stronger control-protocol evidence than line-prefix polling, so the one TorController now owns framed continuation/data replies, asynchronous-event interleaving, whole-reply bounds, control-character admission, and command deadlines. onion-grater's full-command authorization behavior exposed a prefix-whitelist bug; the target filter now requires an exact full-line match. TorProcess was also collapsed onto that deep controller for bootstrap/ownership parsing.

## Final non-adoptions

No second firewall/TUN authority, LD_PRELOAD interception layer, userspace TCP stack, onion-service Kubernetes controller, descriptor balancer, external Tor metadata service, root-mutating Tor appliance, or donor-bundled native Tor binary was imported. Their useful invariants, tests, schemas, and negative lessons remain linked in the adoption ledger. Research donors (TorFlow, TorPS, OnionPerf/CellShift carry-forward) remain observational and do not acquire runtime authority.

## Historical correction layer

Frozen historical ledgers are not edited. Eleven successor resolution rows close earlier future/deferred wording and correct one overclaim: U-S017 no longer implies that production Tor currently enables SOCKS-auth isolation. The current production SocksPort does not enable IsolateSOCKSAuth; torget remains reference evidence only for that isolation dimension.
