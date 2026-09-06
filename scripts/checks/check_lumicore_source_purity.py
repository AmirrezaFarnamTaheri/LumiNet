#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src/packages/lumicore/src"
LABS = ROOT / "labs/lumicore/source-alternates"
CATALOG = ROOT / "labs/lumicore/SOURCE_ALTERNATES.csv"

MOD_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
PATH_RE = re.compile(r"#\s*\[\s*path\s*=\s*\"([^\"]+)\"\s*\]")

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def reachable_rust() -> tuple[set[Path], list[str]]:
    seen: set[Path] = set()
    errors: list[str] = []
    stack = [(SRC / "lib.rs").resolve()]
    while stack:
        path = stack.pop()
        if path in seen:
            continue
        if not path.is_file():
            errors.append(f"missing Rust module file: {path.relative_to(ROOT)}")
            continue
        try:
            path.relative_to(SRC.resolve())
        except ValueError:
            errors.append(f"Rust module escapes source root: {path}")
            continue
        seen.add(path)
        pending_path: str | None = None
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            match = PATH_RE.search(line)
            if match:
                pending_path = match.group(1)
                continue
            match = MOD_RE.search(line)
            if not match:
                continue
            name = match.group(1)
            if pending_path:
                child = (path.parent / pending_path).resolve()
                pending_path = None
            else:
                base = path.parent if path.name in {"lib.rs", "main.rs", "mod.rs"} else path.parent / path.stem
                candidate = base / f"{name}.rs"
                child = candidate if candidate.is_file() else base / name / "mod.rs"
            if not child.is_file():
                errors.append(f"unresolved module {name!r} from {path.relative_to(ROOT)}")
                continue
            stack.append(child.resolve())
    return seen, errors

def main() -> int:
    errors: list[str] = []
    all_files = {p.resolve() for p in SRC.rglob("*") if p.is_file()}
    foreign = sorted(p for p in all_files if p.suffix != ".rs" and p.name != ".context")
    if foreign:
        errors.extend(f"foreign file under Rust source root: {p.relative_to(ROOT)}" for p in foreign)

    all_rs = {p for p in all_files if p.suffix == ".rs"}
    reachable, graph_errors = reachable_rust()
    errors.extend(graph_errors)
    unreachable = sorted(all_rs - reachable)
    if unreachable:
        errors.extend(f"unreachable Rust source under live crate: {p.relative_to(ROOT)}" for p in unreachable)

    if not CATALOG.is_file():
        errors.append("LumiCore source-alternates catalog is missing")
        rows = []
    else:
        with CATALOG.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    if len(rows) != 100:
        errors.append(f"LumiCore source-alternates catalog must preserve 100 baseline files, found {len(rows)}")

    catalog_paths: set[str] = set()
    for row in rows:
        rel = row.get("lab_path", "")
        if not rel.startswith("labs/lumicore/source-alternates/"):
            errors.append(f"invalid LumiCore lab path: {rel}")
            continue
        if rel in catalog_paths:
            errors.append(f"duplicate LumiCore lab path: {rel}")
            continue
        catalog_paths.add(rel)
        path = ROOT / rel
        if not path.is_file():
            errors.append(f"missing LumiCore lab file: {rel}")
            continue
        if str(path.stat().st_size) != str(row.get("size_bytes", "")):
            errors.append(f"size mismatch for LumiCore lab file: {rel}")
        if digest(path) != row.get("sha256"):
            errors.append(f"hash mismatch for LumiCore lab file: {rel}")

    actual = {p.relative_to(ROOT).as_posix() for p in LABS.rglob("*") if p.is_file()}
    missing = sorted(actual - catalog_paths)
    stale = sorted(catalog_paths - actual)
    if missing or stale:
        errors.append(f"LumiCore lab catalog/file mismatch: unlisted={missing[:5]} stale={stale[:5]}")

    print(f"rust_sources={len(all_rs)}/{len(reachable)} reachable foreign={len(foreign)} source_alternates={len(actual)} errors={len(errors)}")
    for item in errors[:100]:
        print("ERROR:", item)
    if len(errors) > 100:
        print(f"ERROR: ... {len(errors)-100} more")
    return 1 if errors else 0

if __name__ == "__main__":
    sys.exit(main())
