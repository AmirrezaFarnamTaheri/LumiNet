# Graphify first-party architecture analysis

## Method

This document preserves a historical Graphify run that was recorded as version 0.9.34 against the LumiNet main source. The 2026-08-09 verification pass could not reproduce that version from public package/release sources, so treat the version string as historical environment metadata, not a current installation instruction. Current runs pin `graphifyy==0.9.26`; CI also verifies the Graphify wheel hash, while transitive Python dependencies remain resolver-managed rather than lockfile-pinned. A second historical pass used this repository's `.graphifyignore` policy to remove vendored, scratch, generated, archived, and test-only material. Community clustering used no LLM backend, so community names are heuristic labels rather than architectural decisions.

Reproduce the production-oriented view with:

```bash
uv tool install graphifyy==0.9.26
make graph
GRAPHIFY_VIZ_NODE_LIMIT=7000 graphify cluster-only . --graph graphify-out/graph.json
```

## Baseline

| View | Code files | Nodes | Edges | Communities |
| --- | ---: | ---: | ---: | ---: |
| Full repository | 505 | 5,359 | 10,028 | 402 |
| First-party production | 355 | 3,839 | 7,031 | 309 |
| Noise removed | 150 (29.7%) | 1,520 (28.4%) | 2,997 (29.9%) | 93 (23.1%) |

The first-party graph contains 6,287 extracted edges (89%) and 744 inferred edges (11%). Refactoring decisions should prioritize extracted edges; inferred name matches are review prompts, not proof of coupling.

## Findings

1. **Vendored and scratch code materially distorted centrality.** The full graph elevated TUIC scratch modules and the vendored `gaio` copy. Excluding them produces a much more useful product topology.
2. **Top-level boundaries are mostly intact.** Only six extracted edges cross the `client`/`server` top-level boundary. Several reported cross-boundary “surprises” are inferred matches caused by generic names.
3. **The dominant `Conn` god node was partly a naming collision.** `server/internal/system/nat.Conn` appeared to connect to unrelated client and server connection types. It has been renamed to `TranslatedConn`, which better describes its responsibility and prevents future graph conflation.
4. **Routing-plugin contracts are a genuine high-connectivity seam.** `RoutingPluginConfig`, `RoutingPluginDescriptor`, `ValidateRoutingPluginConfig`, and `edge_models.go` form the strongest first-party domain cluster. This is a real boundary and should be deepened rather than casually split.
5. **The API router and WebSocket hub remain broad coordination points.** `server/internal/api/router.go`, `server/internal/api/websocket.go`, and `server/internal/api/types.go` deserve interface-focused review, but their centrality is expected for transport composition.
6. **No multi-file import cycle was detected in the first-party view.** The principal risk is responsibility concentration, not a broad cyclic dependency knot.

## Local refactor wave status

### Completed — deepen the routing-plugin boundary

The public descriptor/config/result contracts remain stable while provider ownership is now explicit:

- `b5e19f8` moved provider field allowlists, validation, and warnings behind provider policies.
- `14f968e` moved readiness probes, capabilities, component ownership, observations, and provider evidence into those policies.
- `053f6e8` moved each provider's default descriptor and descriptor-specific secret-policy invariant into the same policy.

The central `routing_plugin_validator.go` fell from more than 1,000 lines in the public-main graph target to 611 lines in the cleaned branch. A deterministic JSON snapshot covering default descriptors, valid and invalid configurations, warnings, redaction, and exact error strings remained byte-identical through the final policy move.

### Completed — separate API composition from endpoint ownership

Commit `f7d0492` reduced `server/internal/api/router.go` to transport lifecycle, global middleware, health/WebSocket setup, and frontend fallback. Authenticated route ownership now lives in focused `routes_scans.go`, `routes_system.go`, and `routes_misc.go` files while `route_catalog.go` remains the route composition boundary.

A package-wide AST route inventory contained 176 registered routes before and after the split with an identical normalized hash. Every moved registrar body also retained its pre-split AST fingerprint.

### Completed — separate JobManager lifecycle from result completion and dispatch

The refined graph identified `JobManager` as a first-party coordination hub. Commit `5cabf1c` keeps lifecycle, persistence, query, and cancellation state in `manager.go`, moves result-to-evidence materialization to `completion.go`, and moves job-type dispatch to `dispatcher.go`. The seven moved function bodies retained identical AST fingerprints.

### Already superseded locally — desktop GUI hotspot

The public-main graph elevated `server/cmd/gui.go` and `gui_helpers.go`, but those files do not exist in the cleaned branch. Desktop GUI ownership has already moved under `desktop/internal/gui`, so recreating the public-main split would be backwards. Any further desktop work should start from the cleaned desktop package rather than the historical graph paths.

### Deferred behind a verification gate — Rust FFI adapters

`core/src/ffi/exports.rs`, `android_jni.rs`, and `ios_ffi.rs` remain intentionally central boundary files and still merit an adapter-thinning pass. This wave does not modify them because the current execution environment has no `cargo`/`rustc`; a structural Rust change should not be accepted without `cargo test`/`cargo check` and `rustfmt` evidence against the cleaned source.

### Next Graphify checkpoint

CI now generates a code-only graph from the cleaned refactor tree on every supported CI event using the pinned public Graphify version. A manually reviewed graph can still become the next checked-in authoritative graph when desired; do not promote historical public-main counts as current topology. Compare node/edge counts, community cohesion, extracted cross-community edges, and the routing/API/JobManager community boundaries rather than optimizing for fewer nodes alone. Commit `graphify-out/graph.json`, `GRAPH_REPORT.md`, and `manifest.json` when that target-state pass is available.

## Interpretation guardrails

- A high degree can indicate a good stable abstraction, not automatically a defect.
- Generic symbol names can produce false inferred edges across languages and packages.
- Community labels are placeholders because no LLM backend was configured.
- The refined graph was generated from the public main source with the cleaned repository's exclusion policy. The local improved workspace contains additional cleanup and organization changes, so the next local Graphify run remains the authoritative target-state graph.
