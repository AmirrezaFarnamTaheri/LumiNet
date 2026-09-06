#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
G = ROOT / "governance/convergence"
DELTA_REL = "governance/convergence/fifth-order-target-delta.csv"
SUCCESSOR_BASELINE = G / "sixth-order-baseline-files.csv"
EXPECTED_BASELINE = 2420
EXPECTED_LEDGER = 11
EXPECTED_PROMOTION_REVIEW = 55
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VALID_STATUS = {"verified", "statically-validated", "reviewed", "inferred", "unverified", "pending"}
VALID_DISPOSITIONS = {"adopted", "adapted", "hardened", "extracted", "recomposed", "synthesized", "inspired-native", "guardrail-derived", "superseded", "rejected-with-reason", "reference-only"}
IMPLEMENTED = {"adopted", "adapted", "hardened", "extracted", "recomposed", "synthesized", "inspired-native", "guardrail-derived", "superseded"}


def read_csv(name: str) -> list[dict[str, str]]:
    path = G / name
    if not path.is_file():
        raise AssertionError(f"missing {name}")
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def digest_path(path: Path) -> tuple[str, str, str]:
    if path.is_symlink():
        target = os.readlink(path)
        return "symlink", hashlib.sha256(target.encode()).hexdigest(), target
    return "file", hashlib.sha256(path.read_bytes()).hexdigest(), "n/a"


def scan_current() -> dict[str, tuple[str, str, str]]:
    # Once sixth-order exists, validate the delivered fifth-order state against
    # its frozen successor baseline so later donor convergence cannot rewrite
    # the fifth-order receipt.
    if SUCCESSOR_BASELINE.is_file():
        out: dict[str, tuple[str, str, str]] = {}
        with SUCCESSOR_BASELINE.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                rel = row["path"].strip()
                if rel == DELTA_REL:
                    continue
                out[rel] = (row["file_type"].strip(), row["sha256"].strip(), row["link_target"])
        return out
    out: dict[str, tuple[str, str, str]] = {}
    for path in sorted(ROOT.rglob("*")):
        if not (path.is_file() or path.is_symlink()):
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel == DELTA_REL or rel.startswith(".git/"):
            continue
        out[rel] = digest_path(path)
    return out


def anchor_exists(node: str) -> bool:
    node = (node or "").strip()
    if node == "n/a":
        return True
    if "#" not in node:
        return False
    path_text, anchor = node.split("#", 1)
    path = ROOT / path_text
    if not path.is_file():
        return False
    raw = path.read_text(encoding="utf-8", errors="replace")
    candidates = {anchor, anchor.split(".")[-1], anchor.replace("-", " "), anchor.replace("-", "_")}
    return any(c and re.search(r"(?<![A-Za-z0-9_])" + re.escape(c) + r"(?![A-Za-z0-9_])", raw, re.I) for c in candidates)


def main() -> int:
    errors: list[str] = []
    try:
        peer_ledger = read_csv("peer-adoption-ledger.csv")
        fourth_sem = read_csv("fourth-order-semantic-reversal.csv")
        baseline_rows = read_csv("fifth-order-baseline-files.csv")
        promotion = read_csv("fifth-order-promotion-review.csv")
        ledger = read_csv("fifth-order-adoption-ledger.csv")
        delta_rows = read_csv("fifth-order-target-delta.csv")
    except AssertionError as exc:
        print(f"fifth-order convergence: FAIL: {exc}", file=sys.stderr)
        return 1

    if len(baseline_rows) != EXPECTED_BASELINE:
        errors.append(f"baseline count {len(baseline_rows)} != {EXPECTED_BASELINE}")
    if len(ledger) != EXPECTED_LEDGER:
        errors.append(f"ledger count {len(ledger)} != {EXPECTED_LEDGER}")
    if len(promotion) != EXPECTED_PROMOTION_REVIEW:
        errors.append(f"promotion review count {len(promotion)} != {EXPECTED_PROMOTION_REVIEW}")

    peer = {r["record_id"]: r for r in peer_ledger if r.get("record_id", "").startswith("SEM")}
    fourth = {r["source_record_id"]: r for r in fourth_sem}
    nonlive = {rid for rid, r in fourth.items() if r.get("current_disposition") in {"reference-only", "rejected-with-reason"}}
    reviews = {r["source_record_id"]: r for r in promotion}
    if set(reviews) != nonlive:
        errors.append(f"promotion review coverage mismatch missing={sorted(nonlive-set(reviews))[:10]} extra={sorted(set(reviews)-nonlive)[:10]}")
    for rid, row in reviews.items():
        src = fourth[rid]
        for field in ["donor", "domain", "value_unit"]:
            if row.get(field) != src.get(field):
                errors.append(f"{rid}: promotion historical field drift {field}")
        if row.get("fourth_order_disposition") != src.get("current_disposition"):
            errors.append(f"{rid}: fourth-order disposition drift")
        if row.get("feature_value") not in {"high", "medium", "low"} or row.get("usability_value") not in {"high", "medium", "low"} or row.get("widget_richness") not in {"high", "medium", "low"}:
            errors.append(f"{rid}: invalid feature-weight rating")
        if not row.get("fifth_order_decision", "").strip() or not row.get("decision_rationale", "").strip():
            errors.append(f"{rid}: incomplete fifth-order re-score")
        if row.get("validation_status") not in VALID_STATUS:
            errors.append(f"{rid}: invalid promotion validation status")

    records = {r["record_id"]: r for r in ledger}
    if len(records) != len(ledger):
        errors.append("duplicate fifth-order adoption record")
    validation_path = G / "fifth-order-validation.md"
    validation = validation_path.read_text(encoding="utf-8") if validation_path.is_file() else ""
    seen_tests: set[str] = set()
    for rid, row in records.items():
        if row.get("disposition") not in VALID_DISPOSITIONS or row.get("validation_status") not in VALID_STATUS:
            errors.append(f"{rid}: invalid disposition/status")
        source_ids = [x for x in row.get("source_peer_record_ids", "").split(";") if x and x != "n/a"]
        if not source_ids:
            errors.append(f"{rid}: missing source peer records")
        for source_id in source_ids:
            if source_id not in peer:
                errors.append(f"{rid}: unknown source peer record {source_id}")
        primary = peer.get(source_ids[0]) if source_ids else None
        if primary and (row.get("donor") != primary.get("donor") or row.get("donor_path") != primary.get("donor_path") or row.get("donor_sha256") != primary.get("donor_sha256") or row.get("donor_symbol") != primary.get("donor_symbol")):
            errors.append(f"{rid}: primary donor evidence not pinned to source semantic")
        if not HEX64.fullmatch(row.get("donor_sha256", "")):
            errors.append(f"{rid}: invalid donor hash")
        for dep in [x for x in row.get("dependency_record_ids", "").split(";") if x and x != "n/a"]:
            if dep not in records:
                errors.append(f"{rid}: unknown fifth-order dependency {dep}")
        if f"### {rid.lower()}" not in validation:
            errors.append(f"{rid}: validation heading missing")
        if row.get("disposition") in IMPLEMENTED:
            for node in row.get("target_nodes", "").split(";"):
                if not anchor_exists(node):
                    errors.append(f"{rid}: target anchor missing {node}")
            test = row.get("test_node", "")
            if test == "n/a" or not anchor_exists(test):
                errors.append(f"{rid}: test anchor missing {test}")
            if test in seen_tests:
                errors.append(f"{rid}: test node reused {test}")
            seen_tests.add(test)
            if row.get("invariant") == "n/a" or row.get("negative_invariant") == "n/a":
                errors.append(f"{rid}: missing invariant")

    # Promoted review rows must point back to at least one live fifth-order record.
    for rid, row in reviews.items():
        refs = [x for x in row.get("promotion_record_ids", "").split(";") if x and x != "n/a"]
        if row.get("fifth_order_decision", "").startswith("promoted"):
            if not refs:
                errors.append(f"{rid}: promoted review missing fifth-order record")
            for ref in refs:
                if ref not in records:
                    errors.append(f"{rid}: unknown promotion record {ref}")

    baseline: dict[str, tuple[str, str, str]] = {}
    for row in baseline_rows:
        path = row.get("path", "").strip()
        if not path or path in baseline:
            errors.append(f"duplicate/empty fifth baseline path {path!r}")
            continue
        if row.get("file_type") not in {"file", "symlink"} or not HEX64.fullmatch(row.get("sha256", "")):
            errors.append(f"fifth baseline {path}: invalid row")
        baseline[path] = (row["file_type"], row["sha256"], row["link_target"])

    current = scan_current()
    expected: dict[str, tuple[str, str, str]] = {}
    for path in sorted(set(baseline) | set(current)):
        before, after = baseline.get(path), current.get(path)
        if before == after:
            continue
        if before is None:
            expected[path] = ("added", "n/a", after[1])
        elif after is None:
            expected[path] = ("deleted", before[1], "n/a")
        else:
            expected[path] = ("modified", before[1], after[1])

    delta: dict[str, dict[str, str]] = {}
    for row in delta_rows:
        path = row.get("path", "").strip()
        if not path or path in delta:
            errors.append(f"duplicate/empty fifth delta path {path!r}")
            continue
        delta[path] = row
        exp = expected.get(path)
        if exp is None:
            errors.append(f"fifth delta {path}: not changed from fourth-order baseline")
            continue
        got = (row.get("change_type"), row.get("fourth_order_sha256"), row.get("current_sha256"))
        if got != exp:
            errors.append(f"fifth delta {path}: change/hash mismatch got={got} expected={exp}")
        for ref in [x for x in row.get("fifth_order_record_ids", "").split(";") if x and x != "n/a"]:
            if ref not in records:
                errors.append(f"fifth delta {path}: unknown accountability id {ref}")
        if not row.get("accountability_class", "").strip() or not row.get("reason", "").strip() or not row.get("verification_node", "").strip():
            errors.append(f"fifth delta {path}: incomplete accountability")
        if row.get("verification_node") != "n/a" and not anchor_exists(row.get("verification_node", "")):
            errors.append(f"fifth delta {path}: missing verification anchor {row.get('verification_node')}")
    missing = sorted(set(expected) - set(delta))
    extra = sorted(set(delta) - set(expected))
    if missing:
        errors.append(f"fifth target delta missing {len(missing)} paths: {missing[:20]}")
    if extra:
        errors.append(f"fifth target delta has {len(extra)} extra paths: {extra[:20]}")

    # Functionality/usability feature invariants.
    manager = (ROOT / "src/apps/daemon/internal/runtime/runtimecore/manager.go").read_text(encoding="utf-8")
    sstp = (ROOT / "src/apps/daemon/internal/runtime/runtimecore/sstp_engine.go").read_text(encoding="utf-8")
    operations = (ROOT / "src/packages/control-ui/src/pages/Operations.tsx").read_text(encoding="utf-8")
    profiles = (ROOT / "src/packages/control-ui/src/pages/Profiles.tsx").read_text(encoding="utf-8")
    qlog = (ROOT / "src/packages/control-ui/src/api/qlog.ts").read_text(encoding="utf-8")
    worker = (ROOT / "src/packages/control-ui/public/sw.js").read_text(encoding="utf-8")
    package = (ROOT / "src/packages/control-ui/package.json").read_text(encoding="utf-8")
    routes = (ROOT / "src/apps/daemon/internal/adapters/api/routes_system.go").read_text(encoding="utf-8")
    if "EngineSSTP" not in manager or "newSSTPEngine" not in sstp or "ppp_options" not in operations:
        errors.append("SSTP runtime/profile promotion incomplete")
    if "/api/system/port-preflight" not in operations or "PreflightLocalPort" not in (ROOT / "src/apps/daemon/internal/adapters/api/handlers_port_preflight.go").read_text(encoding="utf-8"):
        errors.append("port-preflight promotion incomplete")
    for route in ["/update/discover", "/update/stage"]:
        if route not in routes:
            errors.append(f"update route missing {route}")
    if "discoverUpdate" not in operations or "runUpdateAction" not in operations:
        errors.append("update-center workflow incomplete")
    for token in ["Export diagnostic JSON", "parseTransportTrace", "traceCategory", "traceQuery"]:
        if token not in operations:
            errors.append(f"Operations richness missing {token}")
    for token in ["sourceHealthByUrl", "subscriptionInfo", "Refresh now", "openProviderLink"]:
        if token not in profiles:
            errors.append(f"Profiles richness missing {token}")
    if "MAX_TRACE_TEXT_BYTES = 8 * 1024 * 1024" not in qlog or "MAX_TRACE_EVENTS = 100_000" not in qlog:
        errors.append("trace parser bounds missing")
    if "url.pathname.includes('/api/')" not in worker or "request.method !== 'GET'" not in worker:
        errors.append("PWA shell no longer excludes API/non-GET requests")
    if "test:promotions" not in package or "test-feature-promotions.mjs" not in package:
        errors.append("fifth-order feature UI test not wired")

    if errors:
        print(f"fifth-order convergence: errors={len(errors)}", file=sys.stderr)
        for error in errors[:160]:
            print("ERROR:", error, file=sys.stderr)
        return 1
    print(f"fifth-order convergence: baseline={len(baseline_rows)} promotion_review={len(promotion)} records={len(ledger)} changes={len(delta_rows)} errors=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
