#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DAEMON = ROOT / "src" / "apps" / "daemon"
LAB_ROOT = ROOT / "labs" / "daemon" / "modules"
CATALOG = ROOT / "labs" / "daemon" / "modules" / "MODULE_ISLANDS.csv"
MODULE = "github.com/maybeknott/luminet"
SUPPORTED_ROOTS = (
    MODULE,
    MODULE + "/cmd/watchdog",
    MODULE + "/internal/adapters/mobilebind",
)

IMPORT_BLOCK_RE = re.compile(r"(?ms)^\s*import\s*\((.*?)\)")
IMPORT_LINE_RE = re.compile(r'(?m)^\s*import\s+(?:[._A-Za-z][\w.]*)?\s*"([^"]+)"')
QUOTED_RE = re.compile(r'"([^"]+)"')


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_imports(text: str) -> set[str]:
    imports: set[str] = set()
    for match in IMPORT_BLOCK_RE.finditer(text):
        imports.update(QUOTED_RE.findall(match.group(1)))
    imports.update(IMPORT_LINE_RE.findall(text))
    return imports


def package_graph() -> tuple[dict[str, list[Path]], dict[str, set[str]], list[str]]:
    packages: dict[str, list[Path]] = {}
    errors: list[str] = []
    for path in DAEMON.rglob("*.go"):
        if path.name.endswith("_test.go") or "third_party" in path.parts:
            continue
        rel_dir = path.parent.relative_to(DAEMON).as_posix()
        import_path = MODULE if rel_dir == "." else f"{MODULE}/{rel_dir}"
        packages.setdefault(import_path, []).append(path)

    graph = {pkg: set() for pkg in packages}
    for pkg, paths in packages.items():
        for path in paths:
            for imp in parse_imports(path.read_text(encoding="utf-8", errors="ignore")):
                if imp in packages:
                    graph[pkg].add(imp)
                elif imp.startswith(MODULE + "/internal/"):
                    errors.append(
                        f"live package {pkg} imports missing internal package {imp} via "
                        f"{path.relative_to(ROOT).as_posix()}"
                    )
    return packages, graph, errors


def reachable(graph: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    stack = list(SUPPORTED_ROOTS)
    while stack:
        pkg = stack.pop()
        if pkg in seen or pkg not in graph:
            continue
        seen.add(pkg)
        stack.extend(graph[pkg] - seen)
    return seen


def validate_catalog() -> tuple[int, list[str]]:
    errors: list[str] = []
    if not CATALOG.is_file():
        return 0, [f"missing module-island catalog: {CATALOG.relative_to(ROOT)}"]
    rows = list(csv.DictReader(CATALOG.open(encoding="utf-8", newline="")))
    seen: set[str] = set()
    for row in rows:
        lab_path = row.get("lab_path", "").strip()
        source_path = row.get("source_path", "").strip()
        expected_sha = row.get("sha256", "").strip()
        try:
            expected_size = int(row.get("size_bytes", ""))
        except ValueError:
            errors.append(f"invalid size in catalog row: {lab_path!r}")
            continue
        if not lab_path or lab_path in seen:
            errors.append(f"missing/duplicate lab_path in catalog: {lab_path!r}")
            continue
        seen.add(lab_path)
        target = ROOT / lab_path
        if not target.is_file():
            errors.append(f"missing preserved module file: {lab_path}")
            continue
        if source_path and (ROOT / source_path).exists():
            errors.append(f"preserved island still exists under live daemon root: {source_path}")
        if target.stat().st_size != expected_size:
            errors.append(f"size mismatch for preserved module file: {lab_path}")
        if sha256(target) != expected_sha:
            errors.append(f"sha256 mismatch for preserved module file: {lab_path}")

    actual = {
        p.relative_to(ROOT).as_posix()
        for p in LAB_ROOT.rglob("*")
        if p.is_file() and p.parent != LAB_ROOT
    }
    extra = sorted(actual - seen)
    missing_catalog = sorted(seen - actual)
    errors.extend(f"uncatalogued preserved module file: {path}" for path in extra)
    errors.extend(f"catalog path is not a preserved module file: {path}" for path in missing_catalog)
    return len(rows), errors


def main() -> int:
    packages, graph, errors = package_graph()
    for root in SUPPORTED_ROOTS:
        if root not in packages:
            errors.append(f"missing supported daemon root package: {root}")
    live = reachable(graph)
    unreachable = sorted(set(packages) - live)
    errors.extend(f"unreachable live daemon package: {pkg}" for pkg in unreachable)

    catalog_count, catalog_errors = validate_catalog()
    errors.extend(catalog_errors)

    print(
        f"daemon_packages={len(live)}/{len(packages)} reachable "
        f"hidden_islands={len(unreachable)} preserved_module_files={catalog_count} "
        f"errors={len(errors)}"
    )
    for error in errors[:100]:
        print("ERROR:", error)
    if len(errors) > 100:
        print(f"ERROR: ... {len(errors) - 100} more")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
