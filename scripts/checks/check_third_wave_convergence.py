#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
G = ROOT / "governance" / "convergence"
EXPECTED = {"donors": 4, "surfaces": 460, "symbols": 4626, "ledger": 36, "repairs": 1, "baseline": 2376, "corpus": 2827}
HEX64 = re.compile(r"[0-9a-f]{64}")
VALID_STATUS = {"verified", "statically-validated", "reviewed", "inferred", "unverified", "pending"}
VALID_DISPOSITIONS = {
    "adopted", "adapted", "hardened", "extracted", "recomposed", "synthesized",
    "inspired-native", "guardrail-derived", "superseded", "rejected-with-reason", "reference-only",
}
IMPLEMENTED = {"adopted", "adapted", "hardened", "extracted", "recomposed", "synthesized", "inspired-native", "guardrail-derived"}
DELTA_REL = "governance/convergence/third-wave-target-delta.csv"
SUCCESSOR_BASELINE = G / "fourth-order-baseline-files.csv"


def read_csv(name: str) -> list[dict[str, str]]:
    p = G / name
    if not p.is_file():
        raise AssertionError(f"missing {name}")
    with p.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def digest_file(p: Path) -> tuple[str, str, str]:
    if p.is_symlink():
        target = os.readlink(p)
        return "symlink", hashlib.sha256(target.encode()).hexdigest(), target
    return "file", hashlib.sha256(p.read_bytes()).hexdigest(), "n/a"


def scan_current() -> dict[str, tuple[str, str, str]]:
    # A later convergence layer validates its own changes. Once the fourth-order
    # baseline exists, use that immutable snapshot as the delivered third-wave
    # state so legitimate successor edits cannot rewrite the third-wave receipt.
    if SUCCESSOR_BASELINE.is_file():
        out: dict[str, tuple[str, str, str]] = {}
        with SUCCESSOR_BASELINE.open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                rel = row["path"].strip()
                if rel == DELTA_REL:
                    continue
                out[rel] = (row["file_type"].strip(), row["sha256"].strip(), row["link_target"])
        return out
    out: dict[str, tuple[str, str, str]] = {}
    for p in sorted(ROOT.rglob("*")):
        if not (p.is_file() or p.is_symlink()):
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel == DELTA_REL or rel.startswith(".git/"):
            continue
        out[rel] = digest_file(p)
    return out


def anchor_exists(node: str) -> bool:
    if node == "n/a":
        return True
    if "#" not in node:
        return False
    path, symbol = node.split("#", 1)
    p = ROOT / path
    if not p.is_file():
        return False
    raw = p.read_text(encoding="utf-8", errors="replace")
    return bool(symbol) and symbol in raw


def check_corpus() -> list[str]:
    errors: list[str] = []
    raw = (G / "third-wave-corpora.json").read_text(encoding="utf-8")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [f"corpus JSON invalid: {exc}"]
    pur = doc.get("purvpn", {})
    count = pur.get("unique_share_uris_classified")
    if count != EXPECTED["corpus"]:
        errors.append(f"corpus share count {count} != {EXPECTED['corpus']}")
    if sum(pur.get("schemes", {}).values()) != EXPECTED["corpus"]:
        errors.append("corpus scheme counts do not sum to classified URI count")
    if re.search(r"(?i)(?:vless|vmess|trojan|ss|hysteria2|wireguard|purguard)://", raw):
        errors.append("sanitized corpus contains raw share URI")
    if "@" in raw:
        errors.append("sanitized corpus contains endpoint-like @ payload")
    return errors


def main() -> int:
    errors: list[str] = []
    try:
        donors = read_csv("third-wave-donors.csv")
        surfaces = read_csv("third-wave-surfaces.csv")
        symbols = read_csv("third-wave-symbols.csv")
        ledger = read_csv("third-wave-adoption-ledger.csv")
        repairs = read_csv("third-wave-target-repairs.csv")
        baseline_rows = read_csv("third-wave-baseline-files.csv")
        delta_rows = read_csv("third-wave-target-delta.csv")
    except AssertionError as exc:
        print(f"third-wave convergence: FAIL: {exc}", file=sys.stderr)
        return 1

    counts = {"donors": len(donors), "surfaces": len(surfaces), "symbols": len(symbols), "ledger": len(ledger), "repairs": len(repairs), "baseline": len(baseline_rows)}
    for key, want in EXPECTED.items():
        if key == "corpus":
            continue
        if counts.get(key) != want:
            errors.append(f"{key} count {counts.get(key)} != {want}")

    donor_names = {r["donor"] for r in donors}
    if len(donor_names) != len(donors):
        errors.append("duplicate donor")
    for r in donors:
        if not HEX64.fullmatch(r["archive_sha256"]):
            errors.append(f"donor {r['donor']}: invalid archive hash")
        for field in ("archive_members", "directories", "surfaces"):
            try:
                if int(r[field]) < 0:
                    raise ValueError
            except ValueError:
                errors.append(f"donor {r['donor']}: invalid {field}")
    if sum(int(r["surfaces"]) for r in donors) != len(surfaces):
        errors.append("donor surface totals disagree with surface matrix")

    records = {r["record_id"]: r for r in ledger}
    if len(records) != len(ledger):
        errors.append("duplicate third-wave record_id")
    validation = (G / "third-wave-validation.md").read_text(encoding="utf-8") if (G / "third-wave-validation.md").is_file() else ""

    surface_by_key: dict[tuple[str, str], dict[str, str]] = {}
    for r in surfaces:
        key = (r["donor"], r["path"])
        if key in surface_by_key:
            errors.append(f"duplicate surface {key}")
        surface_by_key[key] = r
        if r["donor"] not in donor_names:
            errors.append(f"surface {key}: unknown donor")
        if not HEX64.fullmatch(r["sha256"]):
            errors.append(f"surface {key}: invalid hash")
        ids = [x for x in r["semantic_record_ids"].split(";") if x]
        if not ids:
            errors.append(f"surface {key}: unlinked")
        for rid in ids:
            if rid not in records:
                errors.append(f"surface {key}: unknown record {rid}")
        if r["resolution"] != "resolved-by-third-wave-ledger":
            errors.append(f"surface {key}: unresolved")

    for r in symbols:
        key = (r["donor"], r["path"])
        s = surface_by_key.get(key)
        if s is None:
            errors.append(f"symbol {key}#{r['symbol']}: missing surface")
            continue
        if r["surface_sha256"] != s["sha256"]:
            errors.append(f"symbol {key}#{r['symbol']}: surface hash mismatch")
        ids = [x for x in r["semantic_record_ids"].split(";") if x]
        if not ids:
            errors.append(f"symbol {key}#{r['symbol']}: unlinked")
        for rid in ids:
            if rid not in records:
                errors.append(f"symbol {key}#{r['symbol']}: unknown record {rid}")
        if r["resolution"] != "resolved-by-third-wave-ledger":
            errors.append(f"symbol {key}#{r['symbol']}: unresolved")

    for r in ledger:
        rid = r["record_id"]
        if r["donor"] not in donor_names:
            errors.append(f"{rid}: unknown donor")
        if r["disposition"] not in VALID_DISPOSITIONS:
            errors.append(f"{rid}: invalid disposition")
        if r["validation_status"] not in VALID_STATUS:
            errors.append(f"{rid}: invalid validation status")
        if not HEX64.fullmatch(r["donor_sha256"]):
            errors.append(f"{rid}: invalid donor hash")
        src = surface_by_key.get((r["donor"], r["donor_path"]))
        if src is None:
            errors.append(f"{rid}: donor path absent from surface matrix")
        elif src["sha256"] != r["donor_sha256"]:
            errors.append(f"{rid}: donor hash disagrees with surface")
        if f"### {rid.lower()}" not in validation:
            errors.append(f"{rid}: missing validation heading")
        for dep in [x for x in r["dependency_record_ids"].split(";") if x and x != "n/a"]:
            if dep not in records:
                errors.append(f"{rid}: unknown dependency {dep}")
        if r["disposition"] in IMPLEMENTED:
            if r["target_nodes"] == "n/a":
                errors.append(f"{rid}: implemented/derived record missing target node")
            for node in r["target_nodes"].split(";"):
                if not anchor_exists(node):
                    errors.append(f"{rid}: missing target anchor {node}")
            if r["test_node"] == "n/a" or not anchor_exists(r["test_node"]):
                errors.append(f"{rid}: missing acceptance anchor {r['test_node']}")
            if r["invariant"] == "n/a" or r["negative_invariant"] == "n/a":
                errors.append(f"{rid}: implemented/derived record missing invariants")
        else:
            for node in [x for x in r["target_nodes"].split(";") if x and x != "n/a"]:
                if not anchor_exists(node):
                    errors.append(f"{rid}: missing comparison target anchor {node}")
            if r["test_node"] != "n/a" and not anchor_exists(r["test_node"]):
                errors.append(f"{rid}: missing decision/test anchor {r['test_node']}")
        if r["disposition"] == "rejected-with-reason" and r["negative_invariant"] == "n/a":
            errors.append(f"{rid}: rejected record missing negative invariant")

    errors.extend(check_corpus())

    repair_ids: set[str] = set()
    for r in repairs:
        rid = r["repair_id"]
        if not rid or rid in repair_ids:
            errors.append(f"duplicate/empty repair id {rid!r}")
        repair_ids.add(rid)
        if r["status"] not in VALID_STATUS:
            errors.append(f"{rid}: invalid status")
        if not (ROOT / r["path"]).is_file():
            errors.append(f"{rid}: target missing")
        if not anchor_exists(r["evidence"]):
            errors.append(f"{rid}: evidence anchor missing")

    baseline: dict[str, tuple[str, str, str]] = {}
    for r in baseline_rows:
        path = r["path"]
        if not path or path in baseline:
            errors.append(f"duplicate/empty baseline path {path!r}")
            continue
        if r["file_type"] not in {"file", "symlink"} or not HEX64.fullmatch(r["sha256"]):
            errors.append(f"baseline {path}: invalid row")
        baseline[path] = (r["file_type"], r["sha256"], r["link_target"])

    current = scan_current()
    expected: dict[str, tuple[str, str, str]] = {}
    for path in sorted(set(baseline) | set(current)):
        before = baseline.get(path)
        after = current.get(path)
        if before == after:
            continue
        if before is None:
            expected[path] = ("added", "n/a", after[1])
        elif after is None:
            expected[path] = ("deleted", before[1], "n/a")
        else:
            expected[path] = ("modified", before[1], after[1])

    delta: dict[str, dict[str, str]] = {}
    for r in delta_rows:
        path = r["path"]
        if not path or path in delta:
            errors.append(f"duplicate/empty delta path {path!r}")
            continue
        delta[path] = r
        exp = expected.get(path)
        if exp is None:
            errors.append(f"delta {path}: not changed from second-order baseline")
            continue
        if (r["change_type"], r["second_order_sha256"], r["current_sha256"]) != exp:
            errors.append(f"delta {path}: change/hash mismatch")
        ids = [x for x in r["third_wave_record_ids"].split(";") if x and x != "n/a"]
        for rid in ids:
            if rid not in records:
                errors.append(f"delta {path}: unknown record {rid}")
        if not r["accountability_class"].strip() or not r["reason"].strip() or not r["verification_node"].strip():
            errors.append(f"delta {path}: incomplete accountability")
        node = r["verification_node"]
        if node != "n/a" and not anchor_exists(node):
            errors.append(f"delta {path}: verification anchor missing {node}")
    missing = sorted(set(expected) - set(delta))
    extra = sorted(set(delta) - set(expected))
    if missing:
        errors.append(f"delta missing {len(missing)} paths: {missing[:20]}")
    if extra:
        errors.append(f"delta has {len(extra)} extra paths: {extra[:20]}")

    if errors:
        print("third-wave convergence: FAIL", file=sys.stderr)
        for e in errors[:120]:
            print(f"- {e}", file=sys.stderr)
        if len(errors) > 120:
            print(f"- ... {len(errors)-120} more", file=sys.stderr)
        return 1
    print(
        "third-wave convergence:",
        f"donors={len(donors)} surfaces={len(surfaces)} symbols={len(symbols)} records={len(ledger)} repairs={len(repairs)} baseline={len(baseline_rows)} changes={len(delta_rows)} corpus={EXPECTED['corpus']} errors=0",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
