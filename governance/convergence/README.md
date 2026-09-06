# Historical Value Convergence

This directory is the authoritative evidence index for the post-topology convergence pass. It answers four questions separately so historical value is not confused with live runtime authority.

- `adoption-ledger.csv` — one record per independently meaningful value/disposition decision, with provenance, target ownership, invariants, and validation status.
- `surface-accountability.csv` — source-surface inventory linked back to adoption records.
- `residual-classification.csv` — closed disposition for each material historical/stale class that remained after the structural waves.
- `retirement-register.csv` — target-generated duplicate objects removed after their provenance/value was represented elsewhere.

`python3 scripts/checks/validate_convergence.py` checks the graph, and `make verify-repo` runs it together with baseline topology accounting and the repository audit.

Authority rule: records here explain why material is live, lab/reference-only, superseded, or retired. They do not make labs or historical evidence executable authority.

## External peer convergence

Eight uploaded peer archives are treated as evidence, never as parallel runtime authorities. Current peer evidence is split by accountability level:

- `peer-donors.csv` — archive identities and reconciled counts.
- `peer-surfaces.csv` — all 2979 extracted files/symlinks and hashes.
- `peer-directories.csv` — all 341 donor directories.
- `peer-modules.csv` — all 109 module families and module dispositions.
- `peer-symbols.csv` — all 7351 extracted symbols and inherited/child resolutions.
- `peer-corpora.csv` — large data/test corpora with live-vs-evaluation decisions.
- `peer-adoption-ledger.csv` — 3089 parent+semantic decisions (2979 surface parents + 110 semantic decisions).
- `peer-validation.md` — unique decision/test anchors and claim boundaries.
- `peer-reference-reversal.csv` — explicit second-look disposition for all 80 remaining reference/rejected/superseded semantic decisions.
- `peer-target-repairs.csv` — 4 target-local defects exposed during peer composition, kept separate from donor provenance.
- `peer-target-delta.csv` — 100 changed baseline paths (excluding this manifest itself), each classified and tied to semantic/repair/governance evidence; non-generated rows are SHA-pinned.

`make verify-repo` validates the internal graph; external release verification also re-hashes donor archives and extracted donor surfaces.
## Eighth-order peer convergence: network resilience and authority hardening

The eighth-order pass converges the two most recent uploaded donor batches into LumiNet without creating donor-shaped runtime authorities. Its evidence is deliberately exhaustive rather than sample-based: **23 donor archives, 7,177 archive members, 6,057 file/symlink surfaces, 1,091 directories, 395 recursively bounded module groups, and 9,072 parsed declarations/symbols** are represented in the eighth-order matrices. Large donor trees are recursively split until each splittable accountability group has at most 100 file surfaces, so Firewalla, InviZible, CoreDNS, and other large peers cannot hide behind one umbrella record.

Material target changes are concentrated in three target-native planes:

- **Remote mutation resilience.** `internal/foundation/remoteaction` now coordinates bounded per-action provider cooldown across independent callers, while preserving safety-class replay rules, reconciliation-before-retry, cancellation, hard retry caps, and secret-free state. Aggregate retry/cooldown telemetry is surfaced in `/api/system/status`.
- **DNS resilience.** A shared bounded TTL/LRU primitive replaces unbounded cache maps. The DoH HTTP cache admits only successful DNS answers, coalesces same-key misses, supports stale-if-refresh-error inside a bounded window, rejects malformed/oversized keys before upstream work, and has cancellable maintenance. Weighted DoH and failover resolver caches use the same bounded owner; provider selection/configuration is snapshot-safe and empty-provider state fails closed.
- **Runtime supervision.** Readiness no longer immediately erases restart debt. Only a stable ready interval resets consecutive backoff debt; the rolling circuit-breaker history remains independent and expired history is pruned when recording/evaluating failures, preventing both crash-loop amnesia and stale-history false trips.

The higher-level convergence pass explicitly rejects parallel scheduler/network authorities. InviZible's desired-state and unique-work patterns are absorbed as invariants into LumiNet's existing profile refresh scheduler, process supervisor, durable host-network transaction owner, and mutation reconciliation contract. Se7en's system-proxy recovery reinforces the existing host-network snapshot/apply/verify/rollback owner rather than becoming another service-local mutator. CoreDNS cache semantics outrank shallower godnsagent/dns-over-https-proxy cache patterns.

Safety and licensing are vetoes, not weighted preferences. Firewalla AGPL and GPL-family peers contribute independently rederived semantics or evidence only; no-license repositories are not source-copied. DNS-Persist command-and-control/persistence, ftpscan FTP-bounce mechanics, and InterceptSuite MITM/interception workflows are explicitly rejected as production capabilities; their only admissible value is negative evidence for bounded/verified target boundaries.

Authoritative eighth-order artifacts:

- `eighth-order-source-identity.md`
- `eighth-order-donors.csv`
- `eighth-order-surfaces.csv`
- `eighth-order-directories.csv`
- `eighth-order-modules.csv`
- `eighth-order-symbols.csv`
- `eighth-order-adoption-ledger.csv`
- `eighth-order-supersession-map.csv`
- `eighth-order-target-repairs.csv`
- `eighth-order-license-map.csv`
- `eighth-order-peer-synthesis.md`
- `eighth-order-omission-audit.md`
- `eighth-order-validation.md`
- `eighth-order-baseline-files.csv`
- `eighth-order-target-delta.csv`

`scripts/checks/check_eighth_order_convergence.py` validates the evidence graph, historical baseline layering, exact target delta, live resilience invariants, and the safety-veto boundary. `make verify-repo` includes this gate after the historical seventh-order gate.

