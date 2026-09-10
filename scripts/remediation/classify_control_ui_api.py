#!/usr/bin/env python3
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "src/packages/control-ui"
SRC = UI / "src"
ENTRYPOINTS = [SRC / "main.tsx"]
IMPORT_RE = re.compile(
    r"(?:import|export)\s+(?:[^'\"]*?\s+from\s+)?['\"]([^'\"]+)['\"]|"
    r"import\(\s*['\"]([^'\"]+)['\"]\s*\)"
)
EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".css")


def resolve(source: Path, spec: str) -> Path | None:
    if not spec.startswith('.'):
        return None
    raw = (source.parent / spec).resolve()
    candidates: list[Path] = []
    if raw.suffix:
        candidates.append(raw)
        if raw.suffix in {".js", ".jsx"}:
            candidates.extend([raw.with_suffix(".ts"), raw.with_suffix(".tsx")])
    else:
        candidates.extend(Path(str(raw) + ext) for ext in EXTS)
        candidates.extend(raw / ("index" + ext) for ext in EXTS)
    for candidate in candidates:
        try:
            candidate.relative_to(SRC.resolve())
        except ValueError:
            continue
        if candidate.is_file():
            return candidate
    return None

reachable: set[Path] = set()
stack = [p.resolve() for p in ENTRYPOINTS if p.is_file()]
edges: dict[str, list[str]] = {}
while stack:
    source = stack.pop()
    if source in reachable:
        continue
    reachable.add(source)
    if source.suffix == ".css":
        continue
    text = source.read_text(encoding="utf-8")
    deps: list[str] = []
    for match in IMPORT_RE.finditer(text):
        spec = match.group(1) or match.group(2)
        target = resolve(source, spec)
        if target is None:
            continue
        deps.append(str(target.relative_to(SRC.resolve())))
        if target not in reachable:
            stack.append(target)
    edges[str(source.relative_to(SRC.resolve()))] = sorted(set(deps))

api_root = SRC / "api"
api_files = sorted(
    p.resolve()
    for p in api_root.rglob("*")
    if p.is_file() and p.suffix in {".ts", ".tsx"}
)
reachable_api = sorted(p for p in api_files if p in reachable)
unreachable_api = sorted(p for p in api_files if p not in reachable)

manifest = {
    "schema": "luminet.control-ui-api-authority.v1",
    "entrypoints": [str(p.relative_to(UI)) for p in ENTRYPOINTS],
    "reachable_source_files": len(reachable),
    "api_total": len(api_files),
    "api_reachable": len(reachable_api),
    "api_unreachable": len(unreachable_api),
    "reachable_api": [str(p.relative_to(UI)) for p in reachable_api],
    "unreachable_api": [str(p.relative_to(UI)) for p in unreachable_api],
    "note": "Unreachable means no static or literal dynamic-import path from src/main.tsx. It is not evidence of runtime capability and must not remain in the canonical app API namespace without an explicit compatibility owner.",
}
out = ROOT / "governance/control-ui-api-authority.json"
out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(json.dumps({k: manifest[k] for k in ("reachable_source_files", "api_total", "api_reachable", "api_unreachable")}, indent=2))
