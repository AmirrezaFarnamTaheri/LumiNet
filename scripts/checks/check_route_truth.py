#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
errors = []

retired = [
    "src/apps/daemon/internal/adapters/api/api_extension.go",
    "src/apps/daemon/internal/adapters/api/handlers_covert_tracker.go",
    "src/apps/daemon/internal/adapters/api/handlers_orphans.go",
    "src/apps/daemon/internal/glassui",
]
for rel in retired:
    if (ROOT / rel).exists():
        errors.append(f"retired route surface returned: {rel}")

router = (ROOT / "src/apps/daemon/internal/adapters/api/router.go").read_text(errors="replace")
catalog = (ROOT / "src/apps/daemon/internal/adapters/api/route_catalog.go").read_text(errors="replace")
live = (ROOT / "src/apps/daemon/internal/adapters/api/live_routes.go").read_text(errors="replace")
docs = (ROOT / "docs/api/current-routes.md").read_text(errors="replace")

for token in ('r.GET("/go/:name"', 'SetupExtensionRoutes'):
    if token in router + catalog:
        errors.append(f"stale synthetic route registration remains: {token}")
for token in ('r.Routes()', 'Availability string', 'Capability   string', 'Deprecated   bool', 'routeRuntimeMetadata'):
    if token not in live:
        errors.append(f"runtime route inventory missing metadata contract: {token}")
for stale in ('server/internal/api/route_specs.go', '/api/covert/links', '/go/:name'):
    if stale in docs:
        errors.append(f"route reference still advertises stale surface: {stale}")
if 'GET /api/routes' not in docs or 'runtime authority' not in docs.lower():
    errors.append("route reference does not declare /api/routes runtime authority")

truth = (ROOT / "src/apps/daemon/internal/adapters/api/advanced_route_truth.go").read_text(errors="replace")
if truth.count('Mode: advancedRoute') != 20:
    errors.append("advanced route truth must still classify exactly 20 compatibility registrations")

doctor = (ROOT / "src/apps/daemon/internal/adapters/api/handlers_diagnostic_doctor.go").read_text(errors="replace")
if 'http.StatusNotImplemented' not in doctor or '"supported": false' not in doctor or 'path bonding is unavailable' not in doctor:
    errors.append("path-bonding compatibility route must fail closed and report supported:false")
for retired in (
    "src/apps/daemon/internal/runtime/proxy/path_bonding.go",
    "src/apps/daemon/internal/runtime/proxy/apps_script_front.go",
    "src/apps/daemon/internal/runtime/proxy/sidecar_server.go",
):
    if (ROOT / retired).exists():
        errors.append(f"retired false/dead runtime returned: {retired}")


# The compatibility metrics route must not advertise an empty Prometheus registry as a live capability.
metrics_module = ROOT / "src/apps/daemon/internal/foundation/metrics"
if metrics_module.exists():
    errors.append("retired foundation/metrics module returned; no production metric writers exist")
metrics_handler = (ROOT / "src/apps/daemon/internal/adapters/api/routes_misc.go").read_text(errors="replace")
if "http.StatusNotImplemented" not in metrics_handler or "metrics unavailable" not in metrics_handler:
    errors.append("/api/metrics must fail closed while no production metrics pipeline is initialized")

print(f"route-truth errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
