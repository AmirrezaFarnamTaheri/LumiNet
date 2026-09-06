#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
errors = []

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")

# StartStream is intentionally retained only until the Rust ABI can be changed
# under Cargo. Any new production Go caller invalidates the zero-consumer proof.
go_callers = []
for path in ROOT.rglob("*.go"):
    rel = path.relative_to(ROOT).as_posix()
    if rel == "src/apps/daemon/internal/native/bridge/streaming.go" or rel.startswith("labs/"):
        continue
    text = read(path)
    if re.search(r"\bStartStream\s*\(", text):
        go_callers.append(rel)
if go_callers:
    errors.append("dormant StartStream gained production callers: " + ", ".join(sorted(go_callers)))

streaming = read(ROOT / "src/packages/lumicore/src/ffi/streaming.rs")
if "async fn stream_scan" not in streaming or "// Stub implementation" not in streaming:
    errors.append("stream_scan classification changed; rerun the Cargo-backed capability review")
if "lumicore_stream_start" not in streaming:
    errors.append("stream ABI changed without updating the Wave 17 retirement ledger")

# The old crypto surfaces are allowed to remain compiled only while they are
# zero-consumer. A real consumer requires implementation/security review first.
mlkem_refs = []
aes_refs = []
for path in (ROOT / "src/packages/lumicore/src").rglob("*.rs"):
    rel = path.relative_to(ROOT).as_posix()
    if rel in {"src/packages/lumicore/src/crypto/mlkem.rs", "src/packages/lumicore/src/crypto/aes_gcm.rs", "src/packages/lumicore/src/crypto/mod.rs"}:
        continue
    text = read(path)
    if re.search(r"(?:crate::)?crypto::mlkem\b|\bMlKemEncapsulator\b|\bHybridKexKeypair\b", text):
        mlkem_refs.append(rel)
    if re.search(r"(?:crate::)?crypto::aes_gcm\b|\bAesGcmStream\b", text):
        aes_refs.append(rel)
if mlkem_refs:
    errors.append("dormant crypto/mlkem.rs gained consumers: " + ", ".join(sorted(mlkem_refs)))
if aes_refs:
    errors.append("dormant AesGcmStream gained consumers: " + ", ".join(sorted(aes_refs)))

ci = read(ROOT / ".github/workflows/ci.yml")
makefile = read(ROOT / "Makefile")
if "make verify-release" not in ci:
    errors.append("native retirement gate requires CI to consume make verify-release")
for command in (
    "cargo fmt -- --check",
    "cargo clippy --locked --all-targets -- -D warnings",
    "cargo test --locked",
):
    if command not in makefile:
        errors.append(f"native retirement gate missing release-admission command: {command}")
for target in ("lint-rust", "test-rust"):
    if not re.search(rf"(?m)^verify-release:.*\b{re.escape(target)}\b", makefile):
        errors.append(f"native retirement gate missing verify-release dependency: {target}")

manifest = ROOT / "governance/topology/wave17-native-reachability.json"
if not manifest.is_file():
    errors.append("Wave 17 native reachability manifest is missing")

print(f"native-dormant-surfaces go_callers={len(go_callers)} mlkem_consumers={len(mlkem_refs)} aes_consumers={len(aes_refs)} errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
