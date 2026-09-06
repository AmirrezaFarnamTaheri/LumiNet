#!/usr/bin/env python3
"""Keep the supported Wails desktop product free of unlinked platform sidecars."""
from __future__ import annotations

import csv
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESKTOP = ROOT / "src/apps/desktop"
LAB = ROOT / "labs/desktop/platform-alternates"
CATALOG = LAB / "ALTERNATES.csv"
BASELINE = ROOT / "governance/topology/original-baseline.tsv"
EXPECTED_ROOT = {".context", "README.md", "go.mod", "go.sum", "main.go", "main_test.go", "wails.json"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    errors: list[str] = []
    live_files = {p.relative_to(DESKTOP).as_posix() for p in DESKTOP.rglob("*") if p.is_file()}
    unexpected = sorted(live_files - EXPECTED_ROOT)
    missing = sorted(EXPECTED_ROOT - live_files)
    if unexpected:
        errors.append("unlinked files remain under supported desktop root: " + ", ".join(unexpected))
    if missing:
        errors.append("supported desktop root is missing: " + ", ".join(missing))

    go_sources = [DESKTOP / name for name in ("main.go", "main_test.go")]
    packages = set()
    for path in go_sources:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        m = re.search(r"(?m)^package\s+(\w+)", text)
        if m:
            packages.add(m.group(1))
        if re.search(r'github\.com/maybeknott/luminet/src/apps/desktop/', text):
            errors.append(f"{path.relative_to(ROOT)} imports an undeclared desktop subpackage")
    if packages != {"main"}:
        errors.append(f"supported desktop package set must be exactly {{main}}, got {sorted(packages)}")

    baseline_rows: dict[str, dict[str, str]] = {}
    if BASELINE.is_file():
        baseline_rows = {
            row["path"]: row
            for row in csv.DictReader(BASELINE.open(encoding="utf-8", newline=""), delimiter="\t")
        }
    else:
        errors.append("missing immutable topology baseline")

    rows: list[dict[str, str]] = []
    if not CATALOG.is_file():
        errors.append("missing desktop alternate catalog")
    else:
        rows = list(csv.DictReader(CATALOG.open(encoding="utf-8", newline="")))
        targets: set[str] = set()
        for row in rows:
            target = row.get("lab_path", "")
            if not target:
                errors.append(f"catalog row lacks lab_path: {row}")
                continue
            if target in targets:
                errors.append(f"duplicate desktop alternate target: {target}")
            targets.add(target)
            path = ROOT / target
            if not path.is_file():
                errors.append(f"missing preserved desktop alternate: {target}")
                continue
            if str(path.stat().st_size) != row.get("bytes"):
                errors.append(f"byte-count drift for desktop alternate: {target}")
            if sha256(path) != row.get("sha256"):
                errors.append(f"SHA-256 drift for desktop alternate: {target}")
            original = row.get("original_path", "")
            baseline = baseline_rows.get(original)
            if baseline is None:
                errors.append(f"desktop alternate original path is not in immutable baseline: {original}")
            else:
                if baseline.get("sha256") != row.get("sha256"):
                    errors.append(f"baseline SHA-256 mismatch for desktop alternate: {target}")
                if baseline.get("size") != row.get("bytes"):
                    errors.append(f"baseline byte-count mismatch for desktop alternate: {target}")

        preserved = {
            p.relative_to(ROOT).as_posix()
            for p in LAB.rglob("*")
            if p.is_file() and p not in {CATALOG, LAB / "README.md"}
        }
        if preserved != targets:
            missing_catalog = sorted(preserved - targets)
            stale_catalog = sorted(targets - preserved)
            if missing_catalog:
                errors.append("uncataloged desktop alternates: " + ", ".join(missing_catalog))
            if stale_catalog:
                errors.append("stale desktop alternate catalog rows: " + ", ".join(stale_catalog))

    print(f"desktop_packages={1 if packages == {'main'} else len(packages)}/1 platform_alternates={len(rows)} errors={len(errors)}")
    for error in errors:
        print(f"ERROR: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
