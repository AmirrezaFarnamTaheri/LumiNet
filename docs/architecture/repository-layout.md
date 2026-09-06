# Repository Layout Contract

This document defines the canonical physical layout and dependency direction of LumiNet. Historical paths in audit, topology, porting, labs, and reference evidence describe prior states; they are not live compatibility roots.

## 1. Repository roots

```text
LumiNet/
├── src/           # all live application/shared-package source
│   ├── apps/      # executable/product hosts
│   └── packages/  # reusable/shared packages
├── deploy/        # deployment templates and delivery assets
├── docs/          # human documentation and architecture records
├── governance/    # machine-readable topology/convergence evidence
├── labs/          # governed preserved non-product code/evidence
├── scripts/       # repository tooling module; direct interface documented in scripts/README.md
├── tests/         # cross-module/integration tests
└── third_party/   # external reference/vendor snapshots, not source authority
```

`src/` is the sole live source root. A folder outside `src/` does not become product source merely because it contains code-like files.

## 2. Live source roots

| Path | Ownership |
|---|---|
| `src/apps/daemon/` | Go daemon, CLI/watchdog, local HTTP/WebSocket adapters, workflows, runtime orchestration, persistence, platform integration, and mobile bridge entry points. |
| `src/apps/desktop/` | Supported Wails desktop host. |
| `src/apps/android/` | Canonical Android host: one Activity and one `VpnService`, linked to generated Go mobile bindings. |
| `src/packages/contracts/` | Shared dependency-neutral session-discovery and build-info contracts. |
| `src/packages/control-ui/` | Sole authored React/Vite UI. Checked `dist/` is a fail-closed bootstrap; CI/release replaces it with the production bundle before host packaging. |
| `src/packages/lumicore/` | Rust native core and C ABI implementation. |

Public Go module declarations remain inside their moved module roots, so repository folder containment changes do not create replacement module identities.

## 3. Daemon dependency bands

`src/apps/daemon/internal/` is organized by dependency depth rather than by historical feature accumulation. Cross-band imports may point only to a lower rank. Same-band imports are allowed when they remain within one architectural layer.

```text
src/apps/daemon/internal/
├── foundation/    # rank 0: state/data/config/security/logging/storage primitives
├── native/        # rank 0: Go↔native bridge declarations/adapters
├── protocols/     # rank 1: protocol/framing/reliability implementations
├── platform/      # rank 1: OS/platform mutation and evasion primitives
├── networking/    # rank 2: DNS/routing/geo/proxy configuration/network policy
├── analysis/      # rank 3: diagnostics/probes/scanner/provider classification
├── integrations/  # rank 3: external-system adapters, provisioning, subscriptions
├── runtime/       # rank 4: long-lived/ephemeral runtime orchestration
├── workflows/     # rank 5: jobs and scheduled orchestration
└── adapters/      # rank 6: HTTP/WebSocket and gomobile transport adapters
```

Dependency flow:

```text
foundation/native
      ↓
protocols/platform
      ↓
networking
      ↓
analysis/integrations
      ↓
runtime
      ↓
workflows
      ↓
adapters
      ↓
cmd / executable composition
```

The arrows show **may depend on**, from outer to deeper modules when read bottom-to-top. Lower-ranked code must never import higher-ranked code. `scripts/checks/check_source_structure.py` enforces this rule from actual Go imports.

### 3.1 Band membership

- `foundation`: capabilities, config, crypto, evidence, pingcache, redact, secrets, store, trafficstats.
- `native`: bridge.
- `protocols`: arq, asyncreactor, reliable, tarpit, tlsfragment.
- `platform`: mobilehost, process, system.
- `networking`: dns, geoip, proxyconfig, routing.
- `analysis`: diagnostics, provider, scanner.
- `integrations`: captchaclient, notifier, presets, provision, relayclient, sub.
- `runtime`: decoy, mobilecore, proxy, routingplugin, runtimecore, safety, trust, warp.
- `workflows`: jobs, scheduler.
- `adapters`: api, mobilebind.

New packages belong in the **deepest** band that can own their behavior without importing upward. A new folder is not justified solely to shorten an existing file or package.

## 4. Folder context contract

Every meaningful source folder contains `.context`. It is local architecture/navigation metadata with five jobs:

1. state the folder purpose;
2. summarize direct contents and child ownership;
3. name the interface/dependencies/callers where discoverable;
4. record local invariants and architectural rank;
5. tell maintainers where to look next.

Run `make contexts` after source-folder ownership changes. `scripts/checks/check_source_context.py` makes coverage a repository gate.

Packaging-sensitive generated/copied trees do **not** receive nested `.context` files:

- `src/packages/control-ui/dist/`
- `src/packages/control-ui/public/`
- `src/apps/android/app/src/main/res/`

Their parent context documents them instead, preventing metadata files from entering UI/Android shipped artifacts.

## 5. Authority boundaries

- Live daemon packages must be reachable from a supported root; live code may not import `labs/`.
- `src/packages/control-ui/` is the only authored UI owner. Former desktop/daemon UI copies must not return.
- Gin registrations are route truth; `GET /api/routes` exposes the served inventory. Historical route catalogs are evidence only.
- `src/packages/contracts/` owns shared dependency-neutral contracts, not runtime behavior.
- `src/apps/daemon/internal/native/bridge/lumicore_abi.h` is the single private Go C-declaration surface; Rust owns implementation/layout truth.
- Cargo owns native link requirements. Go/build wrappers consume Cargo metadata rather than creating a second native dependency list.
- `third_party/` is not an import authority. Promoting reference code into live source requires an explicit adoption decision.

## 6. Repository depth rule

Directory depth must encode a real seam or contract. Do not add namespace/category wrappers merely to group one child. Current examples:

- runnable apps are direct peers under `src/apps/` (`daemon/`, `desktop/`, `android/`); there is no namespace-only `mobile/` wrapper for the single supported Android host.
- `scripts/` exposes six direct adapters at its root; internal checks are flat under `scripts/checks/` and generators under `scripts/generate/`.
- daemon labs preserve package/domain identity (`proxy-alternates/`, `scanner-alternates/`, `system-alternates/`, `modules/<package>/`) while governance records the historical wave/retirement reason.
- deployment provider templates are direct children of `deploy/templates/`; canonical relay adapters are direct children of `deploy/relays/` unless a provider requires its own project layout.
- documentation uses the existing semantic groups `architecture/`, `guides/`, `runbooks/`, `plans/`, `audit/`, and `porting/` rather than tool-specific wrappers.
- the gaio third-party module is rooted directly at `third_party/gaio/`.

Depth is retained when it carries semantics: daemon dependency bands; Go/Rust/Android package/module layout; Go `testdata` and vendoring; provider-required paths such as Vercel `api/`; `governance/conductor/`; and immutable provenance locators. ADR-0023 records the decision.

## 7. Non-authoritative preservation/evidence roots

| Path | Purpose |
|---|---|
| `labs/daemon/` | Hash-accounted daemon corpora plus package/domain-organized non-live alternates. |
| `labs/lumicore/` | Unreachable/foreign/native alternates removed from the live Rust graph. |
| `labs/mobile/` | Android fragments/alternates outside the compiled app source set. |
| `labs/desktop/` | Desktop/platform reference material outside supported Wails ownership. |
| `governance/reference/` | Reference-only historical authorities and compatibility evidence. |
| `governance/convergence/` | Adoption/accountability/retirement/split-authority evidence. |
| `governance/topology/` | Original-baseline and relocation/transform accounting. |
| `third_party/gaio/` | Local gaio fork rooted at its actual Go module directory. |

## 8. Verification

Structural changes are incomplete until these pass:

```bash
python3 scripts/checks/check_source_structure.py
python3 scripts/checks/check_source_context.py
python3 scripts/checks/check_tooling_surface.py
python3 scripts/checks/verify_repository_topology.py
python3 scripts/checks/check_daemon_reachability.py
python3 scripts/checks/validate_convergence.py
python3 scripts/checks/repo_audit.py
```

`make verify-repo` composes these with the remaining ownership, FFI, capability-truth, and pruning gates.
