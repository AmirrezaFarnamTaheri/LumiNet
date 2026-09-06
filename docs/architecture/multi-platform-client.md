# Multi-Platform Host Architecture

This document describes the **supported current hosts**. Historical Zygisk, Swift Network Extension, alternate client SDK, and management-bot experiments are preserved in audit/porting/labs evidence and are not shipped product surfaces.

## 1. Shared control UI

`src/packages/control-ui/` is the only authored React/Vite control surface.

- The daemon serves the built bundle over its local HTTP host.
- The Wails desktop application embeds the same bundle.
- The checked `dist/` is intentionally a fail-closed bootstrap. Canonical Make/CI/release builds run the frontend build before compiling/package hosts.

Browser requests cross `ControlTransport`, which owns session selection, authentication headers, response decoding, WebSocket URLs, and diagnostic dispatch. A Wails session-discovery failure is terminal for that session; it cannot downgrade to an unrelated direct HTTP endpoint.

## 2. Desktop host

`src/apps/desktop/` is the supported Windows/macOS/Linux desktop host.

```text
Wails window
   ↓
shared control UI
   ↓
AppBridge.GetSessionConfig
   ↓
contracts/session secure descriptor
   ↓
authenticated daemon HTTP/WebSocket
```

The desktop host owns presentation integration and session discovery only. Daemon runtime, platform mutation, scans, and persistence remain daemon-owned.

## 3. Android VPN host

`src/apps/android/` contains one Activity and one `VpnService` product owner.

```text
LumiNetActivity
    ↓ service lifecycle state
VpnEngineService
    ↓ TUN fd
mobilebind (gomobile adapter)
    ↓
runtime/mobilecore
    ↓
platform/mobilehost + canonical runtime owners
```

`mobilehost` is the platform seam for socket protection/process callbacks. The Android UI reports only state it can derive from the service/runtime; fabricated latency or evasion status is forbidden.

The retired `client-go` compatibility module is not part of the product or release graph. Android consumes the AAR generated directly from the daemon's `internal/adapters/mobilebind` package.

iOS-specific Go/Rust source may remain for guarded platform compatibility or future work, but there is no current iOS host, CI product lane, or release artifact. Reintroducing iOS delivery requires all three plus an explicit architecture decision; a conditional helper-script build is not sufficient.

## 4. Daemon on Linux/macOS/Windows

The Go daemon is the system/runtime owner on desktop operating systems. Platform-specific implementations sit behind the `platform/process` and `platform/system` modules; higher modules call those interfaces instead of spawning independent host runtimes.

Long-lived Tor/Psiphon engines are owned by `runtime/runtimecore`; host-network state changes are owned by `platform/system`; mobile-only callbacks remain in `platform/mobilehost`.

## 5. Deployment and external integrations

Deployment templates and operator assets live under repository-root `deploy/`, outside product source. External relays, subscriptions, provisioning, notifications, and CAPTCHA solving live under the daemon's `integrations` dependency band.

Historical serverless worker, alternate platform client, and management-panel material does not become supported product behavior unless a current owner, caller, tests, capability truth, and delivery path all exist.

## 6. Verification

- `scripts/checks/check_host_products.py` enforces shared UI/desktop ownership, bootstrap truth, Wails fail-closed session behavior, and frontend test/build participation.
- `scripts/checks/check_mobile_product.py`, `check_mobile_binding.py`, `check_mobile_tun_ownership.py`, and `check_mobile_adapter_parity.py` enforce Android/gomobile ownership and capability truth.
- `scripts/checks/check_source_structure.py` and `.context` coverage enforce the source-root/dependency-band contract.
- Release builds rebuild the control UI before daemon/desktop packaging and generate the Android AAR before the APK build.
