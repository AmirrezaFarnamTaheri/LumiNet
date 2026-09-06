#!/usr/bin/env python3
"""Ensure CI retains every native/high-realism verification lane required by the audit."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
GRAPHIFY = (ROOT / "scripts/graphify.sh").read_text(encoding="utf-8")
MAKE = (ROOT / "Makefile").read_text(encoding="utf-8")
RUST_TOOLCHAIN = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
errors: list[str] = []

if 'channel = "1.97.1"' not in RUST_TOOLCHAIN:
    errors.append("rust-toolchain.toml must pin release/compiler authority to Rust 1.97.1")
if 'channel = "stable"' in RUST_TOOLCHAIN:
    errors.append("rust-toolchain.toml must not use the moving stable channel")


for workflow_name, workflow in (("CI", CI), ("release", RELEASE)):
    if "node-version: '22'" in workflow or ("setup-node@" in workflow and "node-version: '22.16.0'" not in workflow):
        errors.append(f"{workflow_name} must pin Node 22.16.0 for release/tooling reproducibility")
    for floating in ("ubuntu-latest", "windows-latest", "macos-latest"):
        if f"runs-on: {floating}" in workflow:
            errors.append(f"{workflow_name} must not use moving runner label {floating}")

    rust_lines = workflow.splitlines()
    rust_setup_indices = [i for i, line in enumerate(rust_lines) if "uses: dtolnay/rust-toolchain@" in line]
    for index, line_index in enumerate(rust_setup_indices, start=1):
        block = "\n".join(rust_lines[line_index : line_index + 8])
        if "toolchain: 1.97.1" not in block:
            errors.append(f"{workflow_name} Rust setup #{index} must explicitly select toolchain 1.97.1")

ci_checks = {
    "Go 1.26.5 pin": "GO_VERSION: '1.26.5'",
    "canonical release admission": "make verify-release",
    "Android AAR build": "gomobile bind -v -o ../../../build/luminet.aar",
    "Android APK build": "gradle --no-daemon :app:assembleDebug",
    "Graphify version pin": "GRAPHIFY_VERSION: '0.9.26'",
    "Graphify wheel hash pin": "GRAPHIFY_WHEEL_SHA256: '2184c5891b71f6b9cea127eb0e92fdd33ab8ee5c254c99312227fc6c5af3ada5'",
    "Graphify install": 'graphifyy==${GRAPHIFY_VERSION}',
    "Graphify artifact hash verification": "sha256sum -c -",
    "Graphify dependency consistency": "python -m pip check",
    "Graphify shared entrypoint": "./scripts/graphify.sh",
    "Graphify timeout": "timeout-minutes: 15",
    "Graphify installed-version check": "version(\"graphifyy\")",
}
for label, needle in ci_checks.items():
    if needle not in CI:
        errors.append(f"CI missing {label}: {needle}")

admission_checks = {
    "Rust formatting": "cargo fmt -- --check",
    "Rust clippy": "cargo clippy --locked --all-targets -- -D warnings",
    "Rust tests": "cargo test --locked",
    "Go daemon CGO tests": "CGO_ENABLED=1 CGO_LDFLAGS=",
    "Go daemon non-CGO tests": "CGO_ENABLED=0 go test ./... -count=1",
    "frontend dependency install": "npm ci",
    "frontend full dependency audit": "npm run audit",
    "frontend tests": "npm test",
    "frontend lint": "npm run lint",
    "frontend build": "npm run build",
}
for label, needle in admission_checks.items():
    if needle not in MAKE:
        errors.append(f"release admission missing {label}: {needle}")


for label, needle in {
    "Graphify code-only extraction": 'graphify extract "$ROOT" --code-only --out "$TMP_OUT" --force',
    "Graphify staged output": 'TMP_OUT=',
    "Graphify safe swap": 'mv -- "$TMP_OUT" "$OUT"',
    "Graphify unrelated-output refusal": 'Refusing to replace existing non-Graphify output path',
    "Graphify output validation": 'check_graphify_output.py" "$TMP_OUT/graph.json"',
    "Graphify local install pin": "uv tool install graphifyy==0.9.26",
}.items():
    if needle not in GRAPHIFY:
        errors.append(f"Graphify entrypoint missing {label}: {needle}")

if "python3 scripts/checks/check_native_verification_coverage.py" not in MAKE:
    errors.append("Makefile verify-repo does not enforce native verification coverage")

for error in errors:
    print(f"ERROR: {error}")
print(f"native-verification-coverage checks={len(ci_checks) + len(admission_checks)} errors={len(errors)}")
raise SystemExit(1 if errors else 0)
