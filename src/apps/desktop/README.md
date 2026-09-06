# LumiNet Desktop Application (Wails v3)

## Ownership

`src/apps/desktop/` is the single supported desktop host. It embeds the canonical React/Vite bundle from `src/packages/control-ui/` and exposes a small Wails bridge for desktop-only operations. It does not own VPN/runtime state.

## Runtime flow

```text
control-ui
   ↓ Wails binding
AppBridge
   ↓ session descriptor / environment override
local daemon HTTP API
```

`AppBridge` has one Wails interface: `GetSessionConfig`. It discovers the daemon through the shared `contracts/session` descriptor and applies `LUMINET_API_URL` / `LUMINET_API_KEY` overrides. All control operations then use the shared control UI's authenticated HTTP transport; desktop does not maintain a second diagnostic or build-info bridge. The retired build-ignored IPC backend is not part of the product.

## Development

```bash
go install github.com/wailsapp/wails/v3/cmd/wails3@latest
cd src/apps/desktop
wails3 dev
```

The frontend source lives in `../../packages/control-ui`; do not create a second desktop frontend tree.

## Production build

From the repository root:

```bash
make build-desktop
```

The desktop module already declares its Wails dependency and embeds the built `control-ui` assets. The daemon must be reachable at the discovered/configured local HTTP endpoint for runtime actions.
