# LumiNet Project Instructions

## Tech Stack
| Layer | Technology | Version / Details |
| :--- | :--- | :--- |
| **Native core** | Rust | Edition 2021 (`src/packages/lumicore/`) |
| **Control-plane daemon** | Go | language 1.26.0, toolchain 1.26.5 (`src/apps/daemon/`) |
| **Shared control UI** | React 19 + TypeScript + Vite | authored source and production embed bundle in `src/packages/control-ui/` |
| **Desktop host** | Wails v3 | one Go host package in `src/apps/desktop/` consuming `controlui.Dist()` |
| **Android** | Go `gomobile` + Android `VpnService` | generated AAR from `src/apps/daemon/internal/adapters/mobilebind/`, linked APK in `src/apps/android/` |
| **Cloud & relay** | JavaScript serverless runtimes | canonical relay policy/adapters under `deploy/relays/` |

## Code Style & Ownership
- **Rust core:** standard Rust 2021 naming and safety conventions. Rust owns FFI implementations; `src/apps/daemon/internal/native/bridge/lumicore_abi.h` is the one private Go declaration surface and is checked by `scripts/checks/check_lumicore_abi.py`.
- **Go daemon:** standard Go package conventions under `src/apps/daemon/internal/`; every live package must be reachable from a supported product/library root.
- **UI:** `src/packages/control-ui/` is the only live React source/embed owner. Do not recreate `src/apps/desktop/frontend/` or `src/apps/daemon/internal/webui/`.
- **Labs:** `labs/` preserves hash-accounted dormant/alternate implementations. Live product code must not import labs directly.
- **Naming:** new canonical owners use product/domain terminology rather than donor project names.

## Testing & Verification
- Canonical static/governance gate: `make verify-repo`.
- Go daemon (full required toolchain): `cd src/apps/daemon && go test ./...` and `go vet ./...`.
- Rust 1.97.1: `cd src/packages/lumicore && cargo test --locked` plus format/Clippy in CI/release.
- Frontend (Node 22.16.0 / npm 10.9.2): `cd src/packages/control-ui && npm test`; release admission runs the full lockfile audit before build tooling.
- Relay contracts: run the four Node contract files under `deploy/relays/` and `deploy/templates/vercel-relay/`.
- Full host build: `./scripts/build-all.sh` or `.\scripts\build-all.ps1`.
- Android: CI/release generate `luminet.aar`, link that exact AAR into the app, and build the APK.

## Key Directory Map
- `src/apps/daemon/` — supported Go daemon/CLI/watchdog and platform integration.
- `src/apps/desktop/` — Wails host only.
- `src/apps/android/` — canonical Android app source (one Activity, one `VpnService`).
- `src/packages/contracts/` — dependency-neutral session-discovery and build-info contracts.
- `src/packages/control-ui/` — shared React source plus canonical embedded bundle.
- `src/packages/lumicore/` — reachable Rust native core.
- `labs/` — governed, non-authoritative preserved alternates.
- `governance/reference/` — historical/reference-only artifacts that must not become active authority.
- `governance/convergence/` — evidence-backed authority/adoption decisions.
- `docs/current-system.md` — current implementation reference.
