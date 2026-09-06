#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
errors = []

required = [
    ROOT / "src/apps/daemon/internal/integrations/sub/ingest.go",
    ROOT / "src/apps/daemon/internal/integrations/sub/fetch.go",
    ROOT / "src/apps/daemon/internal/integrations/sub/profile_service.go",
]
for path in required:
    if not path.exists():
        errors.append(f"missing subscription owner: {path.relative_to(ROOT)}")

for path in [
    ROOT / "src/apps/daemon/internal/runtime/proxy/subscription.go",
    ROOT / "src/apps/daemon/internal/runtime/proxy/proxy_subscription_parser.go",
]:
    if path.exists():
        errors.append(f"retired subscription implementation still active: {path.relative_to(ROOT)}")

product = ROOT / "src/apps/daemon"
for path in product.rglob("*.go"):
    rel = path.relative_to(ROOT)
    text = path.read_text(errors="replace")
    if "internal/proxy" in str(rel) and path.name.endswith("_test.go"):
        pass
    if re.search(r"proxy\.(ParseSubscriptionContent|FetchSubscription|WithCaptchaSolver|WithCoalescer|NewProxySubscriptionParser)\b", text):
        errors.append(f"legacy proxy subscription interface used: {rel}")

profile = (ROOT / "src/apps/daemon/internal/integrations/sub/profile_service.go").read_text(errors="replace")
if "ParseContent(" not in profile:
    errors.append("profile service does not consume canonical sub.ParseContent owner")
if "parser func" in profile or "NodeCounter" in profile:
    errors.append("profile service still exposes parser injection")

print(f"subscription-ownership errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
