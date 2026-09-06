#!/usr/bin/env python3
"""Keep the compatibility per-app surface truthful until real enforcement exists."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
errors: list[str] = []

handler_path = ROOT / "src/apps/daemon/internal/adapters/api/handlers_per_app_proxy.go"
handler = handler_path.read_text(encoding="utf-8", errors="replace") if handler_path.is_file() else ""
if not handler:
    errors.append("per-app compatibility handler is missing")
for token in (
    "Supported bool",
    "Enforced  bool",
    "perAppRoutingUnsupported",
    "http.StatusNotImplemented",
    "rejectPerAppProxyMutation",
):
    if token not in handler:
        errors.append(f"per-app handler is missing capability-truth marker: {token}")
for forbidden in (
    "internal/networking/routing",
    "internal/runtime/proxy",
    "PerAppProxyStore",
    "PerAppPolicy",
    "UpdatePerAppProxy",
):
    if forbidden in handler:
        errors.append(f"per-app handler still persists or delegates inert policy: {forbidden}")

retired = (
    "src/apps/daemon/internal/networking/routing/per_app_policy.go",
    "src/apps/daemon/internal/networking/routing/per_app_proxy.go",
    "src/apps/daemon/internal/runtime/proxy/per_app_proxy.go",
)
for relative in retired:
    if (ROOT / relative).exists():
        errors.append(f"disconnected per-app enforcement implementation returned: {relative}")

for path in (ROOT / "src/apps/daemon").rglob("*.go"):
    if path == handler_path or path.name.endswith("_test.go"):
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    if "ShouldProxy(" in text or "ConfigurePerAppPolicy(" in text or "UpdatePerAppProxy(" in text:
        errors.append(f"disconnected per-app routing decision leaked into active source: {path.relative_to(ROOT)}")

contracts = (ROOT / "src/packages/control-ui/src/api/contracts.ts").read_text(encoding="utf-8", errors="replace")
rules = (ROOT / "src/packages/control-ui/src/pages/Rules.tsx").read_text(encoding="utf-8", errors="replace")
for token in ("supported: boolean", "enforced: boolean", "reason?: string"):
    if token not in contracts:
        errors.append(f"control UI per-app decoder is missing {token}")
if "Per-app routing unavailable" not in rules or "!config.supported || !config.enforced" not in rules:
    errors.append("control UI does not render explicit unavailable per-app routing truth")

mobile_controller = ROOT / "src/apps/daemon/internal/runtime/mobilecore/controller.go"
if mobile_controller.is_file() and "MeasureDelay(" in mobile_controller.read_text(encoding="utf-8", errors="replace"):
    errors.append("unused mobile MeasureDelay compatibility surface returned")

print(f"per-app-capability-truth errors={len(errors)}")
for error in errors:
    print("ERROR:", error)
sys.exit(bool(errors))
