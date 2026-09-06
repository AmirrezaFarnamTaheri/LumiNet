# Current API Route Registry

Status: **current runtime-backed reference**
Runtime authority: `GET /api/routes`
Registration owners: `src/apps/daemon/internal/adapters/api/route_catalog.go`, `routes_*.go`, `panel_routes.go`, and `advanced_route_truth.go`

LumiNet does not maintain a second hand-written route list. The Gin router is the
source of route existence. `/api/routes` enumerates the routes actually registered
for the running daemon and enriches each row with:

- HTTP method and served path;
- canonical workflow/tag classification;
- whether the route is public;
- required capability when one is known;
- runtime availability (`available`, `analysis`, `operational`, or `unavailable`);
- deprecation state.

This prevents documentation from advertising handlers that are not registered and
keeps capability truth separate from mere route presence.

## Stable route families

The authenticated `/api` catalog currently contains these product families:

- scan/evidence: `scans`, `scan-results`, `port-scans`, `proxy-scans`, `dns-scans`, `tls-scans`, `sni-scans`;
- proxy evaluation: `proxies`, `proxy-tests`, `subscriptions`, `presets`, `provider-corpus`, `fptn`;
- system control: `system`, `capabilities`, `server-config`;
- diagnostics/operations: `diagnostics`, `doctor`, `metrics`, `history`, `export`, `jobs`, `telegram`, `routing-plugins`, `speedtest`, `session`.

Public daemon routes are `/health`, `/api/version`, `/api/routes`, and `/ws`.
All other `/api/*` routes use the daemon authentication policy.

## Advanced system routes

Advanced `/api/system/*` compatibility routes remain registered only when the
handler has an explicit entry in `advancedSystemRouteTruth`. Registration means
"this request shape is served"; it does **not** mean the underlying capability is
available. Disconnected legacy controls return `501` with `availability=unavailable`
instead of reporting synthetic success.

## Removed stale surfaces

The following historical surfaces are intentionally not served:

- covert tracker/visit handlers that were present in source but never registered;
- orphan diagnostic/demo handlers that were present in source but never registered;
- synthetic browser-extension profile/rule/shortlink state and its public shortlink redirect family.

Historical route-spec material remains under `governance/reference/` only as
non-authoritative provenance.

## Verification

Run:

```bash
python3 scripts/checks/check_route_truth.py
```

At runtime, inspect the authoritative inventory with:

```text
GET /api/routes
```
