#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
G = ROOT / "governance/convergence"
BASELINE = G / "second-order-baseline-files.csv"
SUCCESSOR_BASELINE = G / "third-wave-baseline-files.csv"
DELTA = G / "second-order-target-delta.csv"
LEDGER = G / "second-order-adoption-ledger.csv"
REPAIRS = G / "second-order-target-repairs.csv"
VALIDATION = G / "second-order-validation.md"
PEER_LEDGER = G / "peer-adoption-ledger.csv"
EXCLUDED_CURRENT = {"governance/convergence/second-order-target-delta.csv"}
EXPECTED_BASELINE_ENTRIES = 2357
EXPECTED_SECOND_ORDER_RECORDS = 12
EXPECTED_REPAIRS = 3
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMPLEMENTED = {
    "adopted", "adapted", "hardened", "extracted", "recomposed",
    "synthesized", "inspired-native", "guardrail-derived", "superseded",
}
VALID_DISPOSITIONS = IMPLEMENTED | {"reference-only", "rejected-with-reason"}


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise RuntimeError(f"missing second-order artifact: {path.relative_to(ROOT)}")
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def hash_path(path: Path) -> tuple[str, str, str]:
    if path.is_symlink():
        target = str(path.readlink())
        return "symlink", hashlib.sha256(target.encode()).hexdigest(), target
    return "file", hashlib.sha256(path.read_bytes()).hexdigest(), "n/a"


def scan_current() -> dict[str, tuple[str, str, str]]:
    # Once a successor convergence layer exists, validate the second-order
    # delivered state against that immutable successor baseline instead of
    # misclassifying legitimate later-wave changes as second-order drift.
    if SUCCESSOR_BASELINE.is_file():
        result: dict[str, tuple[str, str, str]] = {}
        for row in read_csv(SUCCESSOR_BASELINE):
            rel = row["path"].strip()
            if rel in EXCLUDED_CURRENT:
                continue
            result[rel] = (row["file_type"].strip(), row["sha256"].strip(), row["link_target"])
        return result
    result: dict[str, tuple[str, str, str]] = {}
    for path in ROOT.rglob("*"):
        if not (path.is_file() or path.is_symlink()):
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel in EXCLUDED_CURRENT:
            continue
        result[rel] = hash_path(path)
    return result


def anchor_exists(node: str) -> bool:
    if "#" not in node:
        return False
    path_text, anchor = node.split("#", 1)
    path = ROOT / path_text
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="ignore")
    candidates = {anchor, anchor.split(".")[-1], anchor.replace("-", " "), anchor.replace("-", "_")}
    return any(
        candidate and re.search(r"(?<![A-Za-z0-9_])" + re.escape(candidate) + r"(?![A-Za-z0-9_])", text, re.I)
        for candidate in candidates
    )


def main() -> int:
    errors: list[str] = []
    baseline_rows = read_csv(BASELINE)
    delta_rows = read_csv(DELTA)
    ledger_rows = read_csv(LEDGER)
    repair_rows = read_csv(REPAIRS)
    peer_rows = read_csv(PEER_LEDGER)
    validation = VALIDATION.read_text(encoding="utf-8")

    if len(baseline_rows) != EXPECTED_BASELINE_ENTRIES:
        errors.append(f"baseline entries={len(baseline_rows)} expected={EXPECTED_BASELINE_ENTRIES}")
    if len(ledger_rows) != EXPECTED_SECOND_ORDER_RECORDS:
        errors.append(f"second-order records={len(ledger_rows)} expected={EXPECTED_SECOND_ORDER_RECORDS}")
    if len(repair_rows) != EXPECTED_REPAIRS:
        errors.append(f"repairs={len(repair_rows)} expected={EXPECTED_REPAIRS}")

    baseline: dict[str, tuple[str, str, str]] = {}
    for row in baseline_rows:
        path = row["path"].strip()
        if not path or path in baseline:
            errors.append(f"duplicate/empty baseline path: {path!r}")
            continue
        file_type = row["file_type"].strip()
        digest = row["sha256"].strip()
        target = row["link_target"]
        if file_type not in {"file", "symlink"}:
            errors.append(f"baseline {path}: invalid file_type {file_type!r}")
        if not HEX64.fullmatch(digest):
            errors.append(f"baseline {path}: invalid sha256")
        if file_type == "file" and target != "n/a":
            errors.append(f"baseline {path}: regular file has link target")
        baseline[path] = (file_type, digest, target)

    peer = {row["record_id"]: row for row in peer_rows}
    local = {row["record_id"]: row for row in ledger_rows}
    if len(local) != len(ledger_rows):
        errors.append("duplicate second-order record_id")

    for row in ledger_rows:
        rid = row["record_id"]
        if row["disposition"] not in VALID_DISPOSITIONS:
            errors.append(f"{rid}: invalid disposition {row['disposition']!r}")
        source_ids = [x for x in row["source_peer_record_ids"].split(";") if x and x != "n/a"]
        if not source_ids:
            errors.append(f"{rid}: missing source peer record")
        for source_id in source_ids:
            source = peer.get(source_id)
            if source is None:
                errors.append(f"{rid}: unknown source peer record {source_id}")
                continue
            if source["donor"] != row["donor"]:
                errors.append(f"{rid}: donor disagrees with {source_id}")
            if source["donor_path"] == row["donor_path"] and source["donor_sha256"] != row["donor_sha256"]:
                errors.append(f"{rid}: donor hash disagrees with {source_id}")
        if not HEX64.fullmatch(row["donor_sha256"]):
            errors.append(f"{rid}: invalid donor hash")
        for dep in [x for x in row["dependency_record_ids"].split(";") if x and x != "n/a"]:
            if dep not in local:
                errors.append(f"{rid}: unknown local dependency {dep}")
        heading = "### " + rid.lower()
        if heading not in validation:
            errors.append(f"{rid}: missing validation heading")
        if row["test_node"] != "n/a" and not row["test_node"].endswith("#" + rid.lower()):
            errors.append(f"{rid}: test_node must point to unique validation anchor")
        if row["disposition"] in IMPLEMENTED:
            if row["target_nodes"] == "n/a":
                errors.append(f"{rid}: implemented record missing target nodes")
            for node in row["target_nodes"].split(";"):
                if not anchor_exists(node):
                    errors.append(f"{rid}: target node missing/anchor absent: {node}")
            if row["invariant"] == "n/a" or row["negative_invariant"] == "n/a":
                errors.append(f"{rid}: implemented record missing invariants")
        if row["disposition"] == "rejected-with-reason" and row["negative_invariant"] == "n/a":
            errors.append(f"{rid}: rejected record missing negative invariant")

    repair_ids: set[str] = set()
    for row in repair_rows:
        rid = row["repair_id"].strip()
        if not rid or rid in repair_ids:
            errors.append(f"duplicate/empty repair id {rid!r}")
        repair_ids.add(rid)
        if row["status"] not in {"verified", "statically-validated", "reviewed"}:
            errors.append(f"{rid}: invalid repair status")
        target = ROOT / row["path"]
        if not target.is_file():
            errors.append(f"{rid}: repair target missing {row['path']}")
        if not row["reason"].strip() or not row["trigger"].strip() or not anchor_exists(row["evidence"]):
            errors.append(f"{rid}: incomplete/missing repair evidence")

    current = scan_current()
    expected_changes: dict[str, tuple[str, str, str, str]] = {}
    for path in sorted(set(baseline) | set(current)):
        before = baseline.get(path)
        after = current.get(path)
        if before == after:
            continue
        if before is None:
            expected_changes[path] = ("added", "n/a", after[1], after[0])
        elif after is None:
            expected_changes[path] = ("deleted", before[1], "n/a", before[0])
        else:
            expected_changes[path] = ("modified", before[1], after[1], after[0])

    delta: dict[str, dict[str, str]] = {}
    for row in delta_rows:
        path = row["path"].strip()
        if not path or path in delta:
            errors.append(f"duplicate/empty target-delta path: {path!r}")
            continue
        delta[path] = row
        expected = expected_changes.get(path)
        if expected is None:
            errors.append(f"target-delta {path}: path is not changed from peer-converged baseline")
            continue
        change_type, before_hash, after_hash, _ = expected
        if row["change_type"] != change_type:
            errors.append(f"target-delta {path}: change_type {row['change_type']} != {change_type}")
        if row["peer_converged_sha256"] != before_hash:
            errors.append(f"target-delta {path}: peer baseline hash mismatch")
        if row["current_sha256"] != after_hash:
            errors.append(f"target-delta {path}: current hash mismatch")
        if not row["accountability_class"].strip() or not row["reason"].strip() or not row["verification_node"].strip():
            errors.append(f"target-delta {path}: incomplete accountability")
        for local_id in [x for x in row["second_order_record_ids"].split(";") if x and x != "n/a"]:
            if local_id not in local:
                errors.append(f"target-delta {path}: unknown second-order record {local_id}")
        for source_id in [x for x in row["source_peer_record_ids"].split(";") if x and x != "n/a"]:
            if source_id not in peer:
                errors.append(f"target-delta {path}: unknown peer record {source_id}")
        evidence_path = row["verification_node"].split("#", 1)[0]
        if evidence_path and not (ROOT / evidence_path).exists():
            errors.append(f"target-delta {path}: verification path missing {evidence_path}")

    missing = sorted(set(expected_changes) - set(delta))
    extra = sorted(set(delta) - set(expected_changes))
    if missing:
        errors.append(f"target-delta missing {len(missing)} changed paths: {missing[:20]}")
    if extra:
        errors.append(f"target-delta has {len(extra)} extra paths: {extra[:20]}")

    if errors:
        print(
            "second-order convergence:",
            f"baseline={len(baseline)}",
            f"changes={len(expected_changes)}",
            f"records={len(ledger_rows)}",
            f"repairs={len(repair_rows)}",
            f"errors={len(errors)}",
        )
        for error in errors[:120]:
            print("ERROR:", error)
        return 1
    print(
        "second-order convergence:",
        f"baseline={len(baseline)}",
        f"changes={len(expected_changes)}",
        f"records={len(ledger_rows)}",
        f"repairs={len(repair_rows)}",
        "errors=0",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
