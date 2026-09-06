#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOV = ROOT / "governance" / "convergence"
P = "post-refactor-224"
BASELINE_CSV = GOV / f"{P}-baseline-files.csv"
DELTA_CSV = GOV / f"{P}-target-delta.csv"
BASELINE_ROOT = Path(os.environ.get("LUMINET_224_BASELINE_ROOT", "/mnt/data/baseline223"))
DELTA_REL = DELTA_CSV.relative_to(ROOT).as_posix()
EXPECTED_BASELINE_PATHS = 2946


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory(root: Path, *, exclude: set[str] | None = None) -> dict[str, dict[str, str]]:
    exclude = exclude or set()
    rows: dict[str, dict[str, str]] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if rel in exclude:
            continue
        if path.is_symlink():
            target = os.readlink(path)
            rows[rel] = {
                "path": rel,
                "file_type": "symlink",
                "sha256": hashlib.sha256(target.encode()).hexdigest(),
                "link_target": target,
            }
        elif path.is_file():
            rows[rel] = {
                "path": rel,
                "file_type": "file",
                "sha256": sha_file(path),
                "link_target": "n/a",
            }
    return rows


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def load_or_refresh_baseline() -> dict[str, dict[str, str]]:
    if BASELINE_ROOT.is_dir():
        baseline = inventory(BASELINE_ROOT)
        if len(baseline) != EXPECTED_BASELINE_PATHS:
            raise SystemExit(f"baseline path denominator {len(baseline)} != {EXPECTED_BASELINE_PATHS}")
        rows = [baseline[k] for k in sorted(baseline)]
        write_csv(BASELINE_CSV, ["path", "file_type", "sha256", "link_target"], rows)
        return baseline
    rows = read_csv(BASELINE_CSV)
    if len(rows) != EXPECTED_BASELINE_PATHS:
        raise SystemExit(
            f"baseline root unavailable and embedded baseline denominator {len(rows)} != {EXPECTED_BASELINE_PATHS}"
        )
    baseline = {r["path"]: r for r in rows}
    if len(baseline) != len(rows):
        raise SystemExit("duplicate path in embedded post-refactor-224 baseline inventory")
    return baseline


def ledger_path_records() -> dict[str, set[str]]:
    links: dict[str, set[str]] = {}
    for row in read_csv(GOV / f"{P}-adoption-ledger.csv"):
        rid = row["record_id"]
        for field in ("target_nodes", "test_node"):
            value = row.get(field, "n/a")
            if not value or value == "n/a":
                continue
            for node in value.split(";"):
                path = node.split("#", 1)[0]
                if path and path != "n/a":
                    links.setdefault(path, set()).add(rid)
    return links


def reason_for(path: str) -> tuple[str, str]:
    rules = [
        ("src/apps/daemon/internal/networking/kcppolicy/", "bounded shared KCP policy and FEC controls", "src/apps/daemon/internal/networking/kcppolicy/policy_test.go"),
        ("src/apps/daemon/internal/runtime/proxy/kcp_", "real KCP runtime policy/AEAD integration and session identity", "src/apps/daemon/internal/runtime/proxy/kcp_policy_test.go"),
        ("src/apps/daemon/internal/networking/proxyconfig/", "proxy parser guardrails, KCP round-trip semantics, and synthetic protocol oracles", "src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go"),
        ("src/apps/daemon/internal/analysis/diagnostics/", "endpoint/mesh/L7/traffic/routing evidence planners", "scripts/checks/check_post_refactor_224_convergence.py"),
        ("src/apps/daemon/internal/networking/dns/", "read-only DoH resolver pool planning", "src/apps/daemon/internal/networking/dns/doh_pool_plan_test.go"),
        ("src/apps/daemon/internal/integrations/relayclient/", "shared adaptive HTTP relay polling", "src/apps/daemon/internal/integrations/relayclient/relay_conn_state_test.go"),
        ("src/apps/daemon/internal/integrations/presets/", "target-owned Quad9 and routing-related preset expansion", "src/apps/daemon/internal/integrations/presets/presets_test.go"),
        ("src/apps/daemon/internal/foundation/config/", "bounded automatic CAS retry telemetry at the authoritative mutation state machine", "scripts/checks/check_post_refactor_224_convergence.py"),
        ("src/apps/daemon/internal/adapters/api/", "authenticated planner routes and reliability/backpressure status", "scripts/checks/check_post_refactor_224_convergence.py"),
        ("src/packages/control-ui/", "Operations convergence lab and backward-compatible reliability contract parsing", "src/packages/control-ui/scripts/test-post-refactor-224.mjs"),
        ("src/packages/lumicore/src/transport/kcp.rs", "retire print-only parallel Rust KCP placeholder", "scripts/checks/check_post_refactor_224_convergence.py"),
        ("src/packages/lumicore/src/evasion/stack_spoofing.rs", "retire unconsumed stack-spoofing/evasion authority", "scripts/checks/check_post_refactor_224_convergence.py"),
        ("src/packages/lumicore/src/evasion/mod.rs", "remove retired StackSpoofing export", "scripts/checks/check_post_refactor_224_convergence.py"),
        ("governance/convergence/post-refactor-224-", "post-refactor-224 provenance, design, audit, validation, or frozen-baseline evidence", "scripts/checks/check_post_refactor_224_convergence.py"),
        ("governance/topology/relocations.json", "explicit topology accounting for intentional 224 retirements/transforms", "scripts/checks/verify_repository_topology.py"),
        ("scripts/generate/generate_post_refactor_224_", "deterministic 224 evidence/delta regeneration", "scripts/checks/check_tooling_surface.py"),
        ("scripts/checks/check_post_refactor_224_convergence.py", "successor semantic/accountability verification", "scripts/checks/check_post_refactor_224_convergence.py"),
        ("scripts/checks/check_eighth_order_convergence.py", "historical semantic matcher hardened against formatter whitespace", "scripts/checks/check_eighth_order_convergence.py"),
        ("scripts/checks/check_post_refactor_222_convergence.py", "freeze historical 222 accountability against successor baseline", "scripts/checks/check_post_refactor_222_convergence.py"),
        ("scripts/checks/check_post_refactor_223_convergence.py", "freeze historical 223 evidence against exact successor baseline", "scripts/checks/check_post_refactor_223_convergence.py"),
        ("scripts/checks/repo_audit.py", "preserve historical Wave-22 preset hash while admitting explicitly-accounted 224 additions", "scripts/checks/repo_audit.py"),
        ("Makefile", "wire 224 evidence generation and verification into repository tooling", "scripts/checks/check_tooling_surface.py"),
    ]
    for prefix, reason, verify in rules:
        if path == prefix or path.startswith(prefix):
            return reason, verify
    if path.endswith("/.context") or path == ".context":
        return "regenerated source ownership/navigation context", "scripts/checks/check_source_context.py"
    if path in {"CONTEXT.md", "DESIGN.md", "GEMINI.md", "PRODUCT.md", "README.md"}:
        return "regenerated repository context/navigation after 224 ownership changes", "scripts/checks/check_source_context.py"
    return "post-refactor-224 successor change accounted by exact baseline delta", "scripts/checks/check_post_refactor_224_convergence.py"


def main() -> int:
    baseline = load_or_refresh_baseline()
    current = inventory(ROOT, exclude={DELTA_REL})
    record_links = ledger_path_records()
    changed = sorted(set(baseline) | set(current))
    rows: list[dict[str, str]] = []
    for path in changed:
        before = baseline.get(path)
        after = current.get(path)
        if before and after and before["file_type"] == after["file_type"] and before["sha256"] == after["sha256"]:
            continue
        if before is None:
            change_type = "added"
        elif after is None:
            change_type = "deleted"
        else:
            change_type = "modified"
        reason, verify = reason_for(path)
        rows.append({
            "path": path,
            "change_type": change_type,
            "baseline_type": before["file_type"] if before else "n/a",
            "current_type": after["file_type"] if after else "n/a",
            "baseline_sha256": before["sha256"] if before else "n/a",
            "current_sha256": after["sha256"] if after else "n/a",
            "semantic_record_ids": ";".join(sorted(record_links.get(path, set()))) or "n/a",
            "reason": reason,
            "verification_path": verify,
        })
    fields = [
        "path", "change_type", "baseline_type", "current_type", "baseline_sha256", "current_sha256",
        "semantic_record_ids", "reason", "verification_path",
    ]
    write_csv(DELTA_CSV, fields, rows)
    counts = {kind: sum(r["change_type"] == kind for r in rows) for kind in ("added", "modified", "deleted")}
    print(
        f"post-refactor-224 delta: baseline={len(baseline)} changed={len(rows)} "
        f"added={counts['added']} modified={counts['modified']} deleted={counts['deleted']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
