# Technology Stack: LumiNet

## Control Plane (`src/apps/daemon/`)
- **Language:** Go 1.26.0 with repository toolchain Go 1.26.5.
- **HTTP/API:** Gin REST/WebSocket surfaces.
- **Database:** pure-Go SQLite (`modernc.org/sqlite`) with versioned migrations.
- **Native bridge on host builds:** CGO to the Rust static library. Cargo supplies the archive/native link requirements through `scripts/checks/lumicore_link.py`; Go does not hard-code Rust library paths.

## Native Core (`src/packages/lumicore/`)
- **Language:** Rust 2021.
- **Async/runtime:** Tokio and crate-specific networking primitives.
- **FFI ownership:** Rust source owns implementations and layouts. The Go host consumes the checked private header `src/apps/daemon/internal/native/bridge/lumicore_abi.h`; cbindgen/root generated headers are reference-only evidence.

## Shared UI and Desktop
- **UI owner:** `src/packages/control-ui/` (React 19, TypeScript, Vite), including the canonical production embed bundle.
- **Desktop host:** Wails v3 in `src/apps/desktop/`, consuming `controlui.Dist()` rather than owning another frontend tree.
- **Assets:** local bundled assets only; frontend CSS must not depend on remote fonts/assets.

## Mobile
- **Android lifecycle:** `VpnEngineService -> generated mobilebind AAR -> VPNEngine/CoreController -> system.StartTun2Socks`.
- **Mobile bridge:** Android/iOS compile the pure-Go bridge path; host-only Rust CGO files are excluded by build tags.
- **Products:** release produces both `luminet.aar` and a linked Android APK.
- **Alternates:** non-authoritative Android/Rust/Go mobile implementations are hash-preserved under `labs/`.

## CI/CD and Release
- **CI/release authority:** GitHub Actions.
- **Host products:** daemon, watchdog, desktop host, and shared UI bundle.
- **Android products:** AAR plus linked APK.
- **Legacy packaging:** GoReleaser configuration is reference-only under `governance/reference/release/` and must not return to the repository root.
