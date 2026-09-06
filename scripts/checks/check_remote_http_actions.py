#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "governance/convergence/remote-http-actions.csv"
GO_ROOT = ROOT / "src/apps/daemon/internal"

REMOTE_CLASSES = {"idempotent", "reconcile-before-retry", "single-attempt"}
NON_REMOTE_CLASSES = {"not-applicable", "protocol-owned"}
EFFECTS = {"mutation", "side-effect", "query-over-post", "stream-transport"}

# Literal non-read HTTP constructors are the audit denominator. Variable-method
# constructors are covered by the explicit remote-action call registry below.
MUTATION_CONSTRUCTOR = re.compile(
    r"http\.NewRequest(?:WithContext)?\([^\n]*?(?:"
    r'"(POST|PUT|PATCH|DELETE)"|http\.Method(Post|Put|Patch|Delete))'
)
POST_HELPER = re.compile(r"http\.(Post|PostForm)\(")
DYNAMIC_METHOD_CONSTRUCTOR = re.compile(
    r"http\.NewRequestWithContext\([^,\n]+,\s*method\s*,|http\.NewRequest\(\s*method\s*,"
)
READ_WRAPPER_CALL = re.compile(r"\bc\.doReq\([^\n]*?,\s*(http\.Method[A-Za-z]+|\"[A-Z]+\")\s*,")
RAW_PY_MUTATION = re.compile(r"requests\.(?:post|put|patch|delete|request)\(")

# Target-owned action IDs are deliberately stable and human-readable.
ACTION_LITERAL = re.compile(
    r'"((?:cloudflare|ddns|gdrive|gdocs|warp|captcha|notifier|portal|decoy|system)\.[a-z0-9-]+\.[a-z0-9.-]+)"'
)


def load_registry() -> list[dict[str, str]]:
    with REGISTRY.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def go_files() -> list[Path]:
    return sorted(p for p in GO_ROOT.rglob("*.go") if not p.name.endswith("_test.go"))


def anchor_present(path: Path, symbol: str) -> bool:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return bool(re.search(r"(?<![A-Za-z0-9_])" + re.escape(symbol) + r"(?![A-Za-z0-9_])", text))


def main() -> int:
    errors: list[str] = []
    rows = load_registry()
    ids: set[str] = set()
    by_path_method: set[tuple[str, str]] = set()
    dynamic_wrappers = {
        ("src/apps/daemon/internal/runtime/proxy/google_drive_actions.go", "POST"),
        ("src/apps/daemon/internal/runtime/proxy/google_drive_actions.go", "DELETE"),
    }

    for row in rows:
        action = row["action_id"].strip()
        path = row["path"].strip()
        method = row["http_method"].strip().upper()
        effect = row["effect_class"].strip()
        safety = row["safety_class"].strip()
        symbol = row["symbol"].strip()
        if not action or action in ids:
            errors.append(f"duplicate/empty action_id: {action!r}")
        ids.add(action)
        if effect not in EFFECTS:
            errors.append(f"{action}: invalid effect_class {effect!r}")
        if safety not in REMOTE_CLASSES | NON_REMOTE_CLASSES:
            errors.append(f"{action}: invalid safety_class {safety!r}")
        if effect in {"mutation", "side-effect"} and safety not in REMOTE_CLASSES:
            errors.append(f"{action}: remote side effect lacks explicit replay safety class")
        if effect in {"query-over-post", "stream-transport"} and safety in REMOTE_CLASSES:
            errors.append(f"{action}: non-generic action must not inherit generic mutation replay")
        expected_attempts = {"idempotent": "3", "reconcile-before-retry": "3", "single-attempt": "1"}
        if safety in expected_attempts and row["retry_attempts"].strip() != expected_attempts[safety]:
            errors.append(f"{action}: retry_attempts disagrees with safety class")
        target = ROOT / path
        if not target.is_file():
            errors.append(f"{action}: missing path {path}")
        elif not anchor_present(target, symbol):
            errors.append(f"{action}: symbol anchor {symbol!r} missing from {path}")
        by_path_method.add((path, method))

    # Every literal POST/PUT/PATCH/DELETE constructor must be classified. This
    # catches newly added remote writes before they can bypass the registry.
    constructor_count = 0
    for path in go_files():
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        for match in MUTATION_CONSTRUCTOR.finditer(text):
            constructor_count += 1
            method = (match.group(1) or match.group(2) or "").upper()
            if method == "POST": method = "POST"
            elif method == "PUT": method = "PUT"
            elif method == "PATCH": method = "PATCH"
            elif method == "DELETE": method = "DELETE"
            if (rel, method) not in by_path_method and (rel, method) not in dynamic_wrappers:
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"unclassified HTTP constructor {rel}:{line} {method}")
        for match in POST_HELPER.finditer(text):
            constructor_count += 1
            if (rel, "POST") not in by_path_method:
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"unclassified HTTP helper {rel}:{line} POST")

    # Variable-method constructors are a known audit blind spot. Keep their
    # exact owners/counts fixed so a future dynamic wrapper cannot bypass the
    # literal-method denominator silently.
    expected_dynamic = {
        "src/apps/daemon/internal/integrations/provision/cloudflare.go": 2,
        "src/apps/daemon/internal/networking/dns/ddns_updater.go": 1,
    }
    seen_dynamic: dict[str, int] = {}
    for path in go_files():
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        count = len(DYNAMIC_METHOD_CONSTRUCTOR.findall(text))
        if count:
            seen_dynamic[rel] = count
            if rel not in expected_dynamic:
                errors.append(f"unreviewed variable-method HTTP constructor owner: {rel} ({count})")
    for rel, expected in expected_dynamic.items():
        if seen_dynamic.get(rel, 0) != expected:
            errors.append(
                f"variable-method HTTP constructor count changed for {rel}: "
                f"got {seen_dynamic.get(rel, 0)}, want {expected}"
            )

    # Cloudflare's generic doReq wrapper is deliberately read-only; all remote
    # mutations must flow through doMutation instead.
    cloudflare_path = ROOT / "src/apps/daemon/internal/integrations/provision/cloudflare.go"
    cloudflare_text = cloudflare_path.read_text(encoding="utf-8", errors="ignore")
    for match in READ_WRAPPER_CALL.finditer(cloudflare_text):
        method = match.group(1)
        if method not in {"http.MethodGet", '"GET"'}:
            line = cloudflare_text.count("\n", 0, match.start()) + 1
            errors.append(f"Cloudflare read-only doReq used with {method} at line {line}")

    # Production Python must not introduce a raw state-changing requests call.
    # The Telegram deployment template is intentionally routed through its
    # bounded request_idempotent helper instead.
    for base in (ROOT / "deploy", ROOT / "scripts", ROOT / "src"):
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            if "test" in path.name.lower():
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            for match in RAW_PY_MUTATION.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"raw Python remote mutation bypass: {path.relative_to(ROOT)}:{line}")
    telegram_bot = (ROOT / "deploy/templates/telegram-bot/bot.py").read_text(encoding="utf-8")
    if 'request_idempotent("PATCH", url' not in telegram_bot:
        errors.append("Telegram Cloudflare SSL PATCH is not routed through request_idempotent")

    # Every explicit target-owned remote action literal in production code must
    # be registered, and every retry-class registry row must be represented in
    # code. This is the code <-> governance bidirectional check.
    code_actions: set[str] = set()
    for path in go_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        code_actions.update(ACTION_LITERAL.findall(text))
    missing_registry = sorted(code_actions - ids)
    if missing_registry:
        errors.append(f"code action IDs absent from registry: {missing_registry}")
    retry_registry = {r["action_id"] for r in rows if r["safety_class"] in REMOTE_CLASSES}
    missing_code = sorted(retry_registry - code_actions)
    if missing_code:
        errors.append(f"retry-class registry IDs absent from code: {missing_code}")

    if errors:
        print(f"remote HTTP action audit: actions={len(rows)} constructors={constructor_count} errors={len(errors)}")
        for error in errors:
            print("ERROR:", error)
        return 1
    effects: dict[str, int] = {}
    for row in rows:
        effects[row["effect_class"]] = effects.get(row["effect_class"], 0) + 1
    print(
        "remote HTTP action audit:",
        f"actions={len(rows)}",
        f"constructors={constructor_count}",
        f"dynamic_wrappers={sum(seen_dynamic.values())}",
        "python_raw_mutations=0",
        " ".join(f"{key}={effects[key]}" for key in sorted(effects)),
        "errors=0",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
