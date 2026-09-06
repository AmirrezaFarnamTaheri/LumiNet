#!/usr/bin/env python3
"""Require concise ownership context for every meaningful folder under src/."""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"

def excluded(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    rel = relative.as_posix()
    prefixes = (
        "src/packages/control-ui/dist",
        "src/packages/control-ui/public",
        "src/apps/android/app/src/main/res",
    )
    if any(rel == p or rel.startswith(p + "/") for p in prefixes):
        return True
    if any(part in {"node_modules", "target", "build", ".gradle"} for part in relative.parts):
        return True
    return False

required = [SRC] + sorted(p for p in SRC.rglob("*") if p.is_dir() and not excluded(p))
errors: list[str] = []
for directory in required:
    context = directory / ".context"
    rel = directory.relative_to(ROOT).as_posix()
    if not context.is_file():
        errors.append(f"missing .context: {rel}")
        continue
    text = context.read_text(encoding="utf-8", errors="replace")
    for heading in ("Purpose", "Contents", "Interfaces and dependencies", "Invariants"):
        if heading not in text:
            errors.append(f"{rel}/.context: missing section {heading!r}")
    if len(text.strip()) < 180:
        errors.append(f"{rel}/.context: too sparse ({len(text.strip())} chars)")

print(f"source-context required={len(required)} errors={len(errors)}")
for error in errors[:100]:
    print("ERROR:", error)
if len(errors) > 100:
    print(f"ERROR: ... {len(errors)-100} more")
sys.exit(1 if errors else 0)
