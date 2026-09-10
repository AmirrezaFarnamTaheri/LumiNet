#!/usr/bin/env python3
from pathlib import Path
import json
import subprocess

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "src/packages/control-ui"
MANIFEST = ROOT / "governance/control-ui-api-authority.json"
SHADOW = ROOT / "labs/control-ui/api-shadow"

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
unreachable = manifest.get("unreachable_api")
if not isinstance(unreachable, list) or not unreachable:
    raise SystemExit("authority manifest has no unreachable_api relocation set")
if manifest.get("api_unreachable") != len(unreachable):
    raise SystemExit("authority manifest count does not match relocation set")

SHADOW.mkdir(parents=True, exist_ok=True)
readme = SHADOW / "README.md"
readme.write_text(
    "# Control UI API shadow corpus\n\n"
    "This directory contains donor/reference API modules that are **not reachable from the canonical "
    "`src/packages/control-ui/src/main.tsx` application graph**. They are retained outside `src/` for "
    "historical comparison and compatibility research only. Production UI code must not import this "
    "directory. `scripts/checks/check_control_ui_api_authority.py` enforces that boundary.\n",
    encoding="utf-8",
)

moves: list[tuple[str, str, str]] = []
for entry in unreachable:
    rel = Path(entry)
    try:
        shadow_rel = rel.relative_to("src/api")
    except ValueError as exc:
        raise SystemExit(f"unexpected API manifest path {entry}") from exc
    old = UI / rel
    new = SHADOW / shadow_rel
    if not old.is_file():
        raise SystemExit(f"manifest source missing: {old.relative_to(ROOT)}")
    new.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "mv", str(old.relative_to(ROOT)), str(new.relative_to(ROOT))], cwd=ROOT, check=True)
    moves.append((entry, str(shadow_rel).replace('\\', '/'), str(new.relative_to(ROOT)).replace('\\', '/')))

# Preserve historical structural tests/docs by retargeting only exact references
# to files that were just classified as unreachable. Live application imports are
# relative and therefore cannot be silently rewritten to labs by this pass.
tracked = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines()
for tracked_rel in tracked:
    path = ROOT / tracked_rel
    if not path.is_file() or path.is_relative_to(SHADOW):
        continue
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    original = text
    for package_rel, shadow_rel, repo_rel in moves:
        repo_old = f"src/packages/control-ui/{package_rel}"
        text = text.replace(repo_old, repo_rel)
        # package-root paths used by node scripts run from src/packages/control-ui
        text = text.replace(f"'{package_rel}'", f"'../../../labs/control-ui/api-shadow/{shadow_rel}'")
        text = text.replace(f'"{package_rel}"', f'"../../../labs/control-ui/api-shadow/{shadow_rel}"')
        text = text.replace(f"`{package_rel}`", f"`../../../labs/control-ui/api-shadow/{shadow_rel}`")
        # URL-relative references used inside src/packages/control-ui/scripts/*
        text = text.replace(f"'../{package_rel}'", f"'../../../../labs/control-ui/api-shadow/{shadow_rel}'")
        text = text.replace(f'"../{package_rel}"', f'"../../../../labs/control-ui/api-shadow/{shadow_rel}"')
    if text != original:
        path.write_text(text, encoding="utf-8")

manifest.update({
    "schema": "luminet.control-ui-api-authority.v2",
    "api_total": int(manifest.get("api_reachable", 0)),
    "api_unreachable": 0,
    "unreachable_api": [],
    "relocated_reference_count": len(moves),
    "relocated_reference_root": "labs/control-ui/api-shadow",
    "relocated_reference_files": [repo_rel for _, _, repo_rel in moves],
    "note": "Canonical src/api contains only modules reachable from src/main.tsx. The relocated labs corpus is non-authoritative and must never be imported by production source.",
})
MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

print(f"relocated {len(moves)} unreachable API modules to labs/control-ui/api-shadow")
