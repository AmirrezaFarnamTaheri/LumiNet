# LumiNet Compilation, Toolchains, and Build Orchestration

This is the current build contract. Historical build descriptions that generate a repository-root C header or copy Rust archives into fixed linker directories are no longer authoritative.

## Host build graph

```text
Rust source --Cargo--> liblumicore static archive + native-static-libs metadata
                              |
                              v
scripts/checks/lumicore_link.py -----+----> CGO_LDFLAGS
                              |
Go daemon --------------------+----> luminet
Go watchdog (CGO off) --------------> watchdog

src/packages/control-ui --Vite----------> canonical dist bundle
                                       |          |
                                       v          v
                                  daemon embed  Wails host
```

The Go bridge declarations are checked in at `src/apps/daemon/internal/native/bridge/lumicore_abi.h`. `scripts/checks/check_lumicore_abi.py` verifies the ABI version, C/Rust struct layouts (including packed scan structs), every Rust export actually called by Go, and rejects inline/parallel declaration authorities. There is no active cbindgen step.

## Required repository versions

- Go language version: 1.26.0; toolchain: 1.26.5 (`.go-version`, `go.work`).
- Node: 22.16.0 (`.nvmrc`) with its bundled npm 10.9.2; `package.json` declares the same exact package-manager version and `package-lock.json` is the dependency authority.
- Rust: 1.97.1 (`rust-toolchain.toml`); every CI/release Rust setup step explicitly selects the same compiler version.
- Host CGO builds require a compatible C compiler/linker for the target.
- Android CI/release uses JDK 17 and Gradle provisioned by the pinned setup action; the project currently does not carry a local Gradle wrapper.

## Host commands

```bash
make build              # Rust core + daemon/watchdog
make build-web          # shared React/Vite bundle
make build-desktop      # shared UI + Wails host
make build-all          # host daemon/watchdog + desktop
make verify-repo        # structural/governance/contract gate
make verify-release     # canonical release-admission tests + lint + verification
```

Windows may use `scripts/build-all.ps1`; Linux/macOS may use `scripts/build-all.sh`. Both obtain LumiCore link requirements from `scripts/checks/lumicore_link.py` instead of hard-coded archive/system-library paths.

## Android build graph

The Android product does not inherit the host Rust-CGO boundary:

```text
src/apps/daemon/internal/adapters/mobilebind
        |
   gomobile bind (-javapkg=com.luminet)
        |
   build/luminet.aar
        |
copy exact AAR -> src/apps/android/app/libs/luminet.aar
        |
Gradle assembleDebug / assembleRelease
        |
linked APK
```

The current mobile build targets Android. The AAR exposes `VPNEngine`; the canonical service is `src/apps/android/app/src/main/java/com/luminet/android/VpnEngineService.kt`. Host-only C bridge files are excluded from Android by build tags, so gomobile selects the pure-Go bridge path. iOS-specific source/build tags do not constitute a supported iOS host; no iOS framework or app is built or released.

## CI and release

- `make verify-release` is the canonical release-admission interface. It composes repository-tooling tests, ABI and preservation-ledger validation, `make verify-repo`, Go/Rust dependency vulnerability audits, Rust format/Clippy/tests, linked Go vet plus CGO/non-CGO tests, desktop tests, and control-UI full dependency audit/tests/lint/build. The npm audit includes dev/build dependencies because release admission executes those tools.
- `.github/workflows/ci.yml` consumes `make verify-release` before the full linked host build rather than duplicating those checks. Node is pinned to 22.16.0, Rust to 1.97.1, and workflow runner OS families use explicit Ubuntu 24.04, Windows 2025, and macOS 15 labels instead of moving `*-latest` aliases. CI installs pinned `govulncheck`/`cargo-audit` binaries and supplies the event-specific preservation base SHA; tag release supplies the previous-release base. Governance commands receive repository root and discover canonical `governance/conductor/` authorities internally; path flags are override-only. Platform lanes retain checks that require their target OS, including the macOS Keychain provider and Windows CGO tests.
- `.github/workflows/release.yml` consumes the same admission interface before any platform build. The admitted job uploads the verified control-UI bundle, and Linux/Windows/macOS packaging downloads that exact artifact. Windows release packaging vets/tests Windows CGO code; macOS arm64 packaging exercises the native Keychain provider. Android builds the AAR and linked release APK. Published artifacts retain SBOM/provenance steps.
- Local Git checkouts default preservation comparison to `HEAD^`; CI and tag workflows override `PRESERVATION_BASE_SHA` with event/release-aware bases. Source archives without Git history therefore cannot claim release admission unless an explicit valid base is supplied.
- `governance/reference/release/.goreleaser.yaml` is historical/reference evidence only.

## Proof boundaries

A static gate is not a substitute for a full toolchain build. If Go 1.26.5, Cargo/Rust, Android Gradle, or target native toolchains are unavailable locally, record that limitation and rely on the checked-in CI/release lane for that proof rather than weakening version requirements.


The supported direct repository-tooling interface is documented in `scripts/README.md`; other top-level script implementation requires a live Make/CI/script caller.
