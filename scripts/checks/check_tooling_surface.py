#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
errors: list[str] = []

DIRECT_TOOLS = {
    "build-all.sh",
    "build-all.ps1",
    "dev.sh",
    "dev.ps1",
    "graphify.sh",
    "mobile_bind.sh",
}

RETIRED_PATHS = {
    "scripts/analyze_to_port.py": "one-off TO PORT analyzer with a developer-specific absolute path and no live caller",
    "scripts/conv_parser.py": "zero-width session experiment with no live product/tooling caller",
    "scripts/dspy_evolution.py": "dummy prompt-evolution experiment with no live caller",
    "scripts/fetch_windivert.json": "untrusted WinDivert fetch manifest with placeholder integrity data",
    "scripts/fetch_windivert.ps1": "disconnected WinDivert fetch adapter with no trusted artifact contract",
    "scripts/graphify.ps1": "zero-caller Graphify adapter without transactional validation/rollback parity",
    "scripts/install/README.md": "unpublished Scoop installer documentation that contradicts current release products",
    "scripts/install/luminet.json": "unpublished Scoop manifest with placeholder hashes and unsupported Windows arm64 artifact",
    "scripts/scoop_paths.json": "historical Scoop path corpus with no current installer owner",
    "scripts/validate_abi_manifest.go": "zero-caller compatibility launcher superseded by scripts/cmd/validate-abi-manifest",
    "scripts/validate_preservation_ledger.go": "zero-caller compatibility launcher superseded by scripts/cmd/validate-preservation-ledger",
}

for relative, reason in RETIRED_PATHS.items():
    if (ROOT / relative).exists():
        errors.append(f"retired tooling surface returned: {relative} ({reason})")

readme_path = SCRIPTS / "README.md"
if not readme_path.is_file():
    errors.append("scripts/README.md is missing; supported direct tooling interface is undocumented")
    readme = ""
else:
    readme = readme_path.read_text(encoding="utf-8", errors="replace")

for name in sorted(DIRECT_TOOLS):
    if not (SCRIPTS / name).is_file():
        errors.append(f"documented direct tool is missing: scripts/{name}")
    if f"`{name}`" not in readme:
        errors.append(f"scripts/README.md does not document direct tool: {name}")

# The scripts root is the public tooling interface. Internal implementation is
# allowed only under the shallow `checks/` and `generate/` directories (plus
# Go's language-imposed cmd/internal/vendor module layout), and every executable
# implementation file must have a live Make/CI/script caller.
allowed_root_files = DIRECT_TOOLS | {"README.md", "go.mod", "go.sum"}
allowed_root_dirs = {"checks", "generate", "cmd", "internal", "vendor"}
for path in sorted(SCRIPTS.iterdir()):
    if path.is_file() and path.name not in allowed_root_files:
        errors.append(f"unexpected scripts-root file outside direct interface: scripts/{path.name}")
    if path.is_dir() and path.name not in allowed_root_dirs:
        errors.append(f"unexpected scripts-root directory: scripts/{path.name}")

callers: list[tuple[str, str]] = []
for path in [ROOT / "Makefile"]:
    if path.is_file():
        callers.append((path.relative_to(ROOT).as_posix(), path.read_text(encoding="utf-8", errors="replace")))
for base in [ROOT / ".github", SCRIPTS]:
    if not base.exists():
        continue
    for path in base.rglob("*"):
        if not path.is_file() or path == Path(__file__).resolve():
            continue
        if path.suffix.lower() not in {".py", ".sh", ".ps1", ".go", ".yml", ".yaml"}:
            continue
        callers.append((path.relative_to(ROOT).as_posix(), path.read_text(encoding="utf-8", errors="replace")))

for base in (SCRIPTS / "checks", SCRIPTS / "generate"):
    if not base.is_dir():
        errors.append(f"missing internal tooling directory: {base.relative_to(ROOT).as_posix()}")
        continue
    for path in sorted(base.iterdir()):
        if not path.is_file() or path.suffix.lower() not in {".py", ".go"}:
            continue
        relative = path.relative_to(ROOT).as_posix()
        refs = [caller for caller, body in callers if caller != relative and (relative in body or path.name in body)]
        if not refs:
            errors.append(f"internal tooling implementation has no live caller: {relative}")

print(f"tooling-surface direct={len(DIRECT_TOOLS)} retired={len(RETIRED_PATHS)} errors={len(errors)}")
for error in errors:
    print("ERROR:", error)
raise SystemExit(1 if errors else 0)
