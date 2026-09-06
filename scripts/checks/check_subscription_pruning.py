#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
errors = []
retired = [
    ROOT / "src/apps/daemon/internal/integrations/sub/subscription_aggregator.go",
    ROOT / "src/apps/daemon/internal/integrations/sub/profile_parser.go",
    ROOT / "src/apps/daemon/internal/integrations/sub/tg_channel_scraper.go",
    ROOT / "src/apps/daemon/internal/integrations/sub/begzar_decryptor.go",
    ROOT / "src/apps/daemon/internal/integrations/subparser",
]
for path in retired:
    if path.exists():
        errors.append(f"stale subscription corpus still active: {path.relative_to(ROOT)}")

fetch_text = (ROOT / "src/apps/daemon/internal/integrations/sub/fetch.go").read_text(errors="replace")
if "WithCoalescer" in fetch_text or "coalescerFromContext" in fetch_text:
    errors.append("stale subscription coalescer injection remains in internal/sub/fetch.go")

for path in (ROOT / "src/apps/daemon").rglob("*.go"):
    text = path.read_text(errors="replace")
    if "internal/subparser" in text:
        errors.append(f"active subparser dependency: {path.relative_to(ROOT)}")

print(f"subscription-pruning errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
