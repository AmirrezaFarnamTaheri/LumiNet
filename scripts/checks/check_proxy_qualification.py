#!/usr/bin/env python3
from pathlib import Path
import hashlib
import re

ROOT = Path(__file__).resolve().parents[2]
errors = []

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")

owner = read(ROOT / "src/apps/daemon/internal/runtime/proxy/qualification.go")
cmd = read(ROOT / "src/apps/daemon/cmd/proxy.go")
jobs = read(ROOT / "src/apps/daemon/internal/workflows/jobs/runners.go")
parser_path = ROOT / "src/apps/daemon/internal/runtime/proxy/parser.go"
private_aliases = read(ROOT / "src/apps/daemon/internal/runtime/proxy/proxyconfig_internal.go")
preserved_parser = ROOT / "labs/daemon/proxy-alternates/parser.go"

if "func Qualify(" not in owner or "NewCoreManager" not in owner or "NewProxyTester" not in owner:
    errors.append("qualification owner does not contain the complete core/tester orchestration")
if "proxy.Qualify(" not in cmd or "proxy.Qualify(" not in jobs:
    errors.append("CLI and jobs do not both cross the qualification seam")

for root in (ROOT / "src/apps/daemon/cmd", ROOT / "src/apps/daemon/internal/workflows/jobs"):
    for path in root.rglob("*.go"):
        if path.name.endswith("_test.go"):
            continue
        data = read(path)
        if "NewCoreManager(" in data or "NewProxyTester(" in data:
            errors.append(f"caller still owns qualification construction: {path.relative_to(ROOT)}")

if parser_path.exists():
    errors.append("legacy parser compatibility facade remains active: src/apps/daemon/internal/runtime/proxy/parser.go")
if not preserved_parser.exists():
    errors.append("retired Wave 11 parser facade is not preserved under governed labs")
elif hashlib.sha256(preserved_parser.read_bytes()).hexdigest() != "c654a34732a449180db3dfe9614d1e7bc9cdd75c8b89eed28dba734c3e2a070f":
    errors.append("preserved Wave 11 parser facade changed bytes")
for exported in ("ProxyConfig", "ProxyProtocol", "ParseProxyURI", "ParseProxyList", "SanitizeAndDedupe", "ExtractRealityParams", "IsSuspicious"):
    if re.search(rf"(?m)^(?:type\s+{exported}\b|\s*{exported}\s*=)", private_aliases):
        errors.append(f"proxy implementation glue re-exports caller-facing parser symbol: {exported}")

for path in (ROOT / "src/apps/daemon/cmd", ROOT / "src/apps/daemon/internal/adapters/api", ROOT / "src/apps/daemon/internal/workflows/jobs"):
    for source in path.rglob("*.go"):
        if source.name.endswith("_test.go"):
            continue
        data = read(source)
        if re.search(r"proxy\.(ParseProxyURI|ParseProxyList|SanitizeAndDedupe|ExtractRealityParams|IsSuspicious)\b", data):
            errors.append(f"active external caller still uses parser compatibility facade: {source.relative_to(ROOT)}")
        if re.search(r"proxy\.(ProxyConfig|ProxyProtocol|Protocol[A-Za-z0-9_]+)\b", data):
            errors.append(f"active external caller still uses parser type/constant facade: {source.relative_to(ROOT)}")

print(f"proxy-qualification-ownership errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
