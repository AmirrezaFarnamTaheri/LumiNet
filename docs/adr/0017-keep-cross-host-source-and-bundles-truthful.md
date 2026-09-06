# Keep cross-host source and bundles truthful

Status: Accepted

## Context and Problem Statement

After the source-layout and deep-module refactors, several cross-host surfaces still implied capabilities or products that no shipped host consumed. The `client-go` module was not imported by any live product and its portable binding reported runtime unavailability; desktop retained a build-ignored alternate backend; Android rendered fabricated latency/evasion status; and the checked control-UI `dist/` contained an obsolete functional bundle even though daemon and desktop embed that directory.

The authored control UI also depends on desktop session discovery when running under Wails. Falling back to default direct HTTP after a Wails discovery error would bypass the desktop session-authority decision. Conversely, browser mode legitimately needs direct HTTP configuration.

## Considered Options

- Preserve compatibility surfaces and stale checked bundles for convenience.
- Check in a full generated frontend bundle and manually keep it synchronized with authored source.
- Retire unconsumed host surfaces, keep one live implementation per host, and make generated/bootstrap states explicit and fail closed.

## Decision Outcome

Keep only product source with a demonstrated host or release consumer. Retire unused compatibility modules rather than treating tests as product reachability. Desktop uses one Wails `AppBridge` whose only host interface is session discovery; control operations use the same authenticated daemon HTTP transport in browser and desktop modes. Android displays only runtime-backed state; shared contracts contain only genuinely shared ownership.

Treat `src/packages/control-ui/src/` as authored UI source. The tracked `dist/` may be either a fail-closed unbuilt bootstrap or a generated bundle that contains the current session-transport behavior and no legacy backend endpoints. Canonical Make and release builds must build the control UI before compiling hosts that embed `dist/`, and CI must run the UI contract/transport tests.

Under Wails, failure to obtain a valid session configuration fails closed. Direct HTTP fallback is permitted only when no Wails session bridge exists (browser/development mode).

## Consequences

Checked source cannot silently advertise an unsupported SDK, fake telemetry, alternate desktop backend, or stale functional frontend bundle. Local source checkouts remain safe even without frontend dependencies because the bootstrap does not contact a daemon. Producing a normal daemon/desktop binary through canonical build paths now requires a successful frontend build.

Historical compatibility code and generated bundles remain recoverable through Git/provenance artifacts rather than active source. Frontend and host verification must accept both valid `dist/` states while rejecting legacy endpoints and unsafe Wails fallback behavior.
