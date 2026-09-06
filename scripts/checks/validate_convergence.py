#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "governance/convergence/adoption-ledger.csv"
SURFACES = ROOT / "governance/convergence/surface-accountability.csv"
RESIDUALS = ROOT / "governance/convergence/residual-classification.csv"
RETIREMENTS = ROOT / "governance/convergence/retirement-register.csv"
SYNTHESIS = ROOT / "governance/convergence/split-brain-synthesis.csv"
BASELINE = ROOT / "governance/topology/original-baseline.tsv"

ALLOWED_DISPOSITIONS = {
    "adopted", "adapted", "hardened", "extracted", "recomposed", "synthesized",
    "inspired-native", "guardrail-derived", "superseded", "rejected-with-reason",
    "reference-only",
}
ALLOWED_VALIDATION = {"verified", "statically-validated", "reviewed", "inferred", "unverified", "pending"}
REQUIRED_RESIDUAL_CLASSES = {
    "daemon-labs", "android-labs", "desktop-labs", "porting-evidence",
    "excluded-peer-evidence", "tpm-legacy-migration", "native-export-boundaries",
    "refactor-source-archives", "duplicate-root-parsers", "completed-legacy-task-notes",
    "review-policy", "dated-audit-evidence",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
errors: list[str] = []


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        errors.append(f"missing convergence artifact: {path.relative_to(ROOT)}")
        return []
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    except (OSError, csv.Error) as exc:
        errors.append(f"invalid convergence CSV {path.relative_to(ROOT)}: {exc}")
        return []


ledger = read_csv(LEDGER)
surfaces = read_csv(SURFACES)
residuals = read_csv(RESIDUALS)
retirements = read_csv(RETIREMENTS)
synthesis = read_csv(SYNTHESIS)

ids: set[str] = set()
for row in ledger:
    rid = row.get("record_id", "")
    if not rid or rid == "n/a":
        errors.append("adoption ledger contains missing/n/a record_id")
        continue
    if rid in ids:
        errors.append(f"duplicate adoption record_id: {rid}")
    ids.add(rid)
    sha = row.get("donor_sha256", "")
    if not SHA256.fullmatch(sha):
        errors.append(f"adoption record has invalid donor_sha256: {rid}: {sha}")
    if row.get("disposition") not in ALLOWED_DISPOSITIONS:
        errors.append(f"adoption record has invalid disposition: {rid}: {row.get('disposition')}")
    if row.get("validation_status") not in ALLOWED_VALIDATION:
        errors.append(f"adoption record has imprecise validation status: {rid}: {row.get('validation_status')}")
    if row.get("risk_tier") in {"high", "critical"} and row.get("validation_status") in {"pending", "unverified", "inferred"}:
        errors.append(f"high-risk adoption record remains unresolved: {rid}: {row.get('validation_status')}")
    for node in row.get("target_nodes", "").split(";"):
        node = node.strip()
        if not node or node == "n/a":
            continue
        path_text = node.split("#", 1)[0]
        if path_text.startswith(("http:", "https:", "GET ", "POST ", "PUT ", "PATCH ", "DELETE ")):
            continue
        if not (ROOT / path_text).exists():
            errors.append(f"adoption record target node path missing: {rid}: {path_text}")

for row in surfaces:
    sha = row.get("sha256", "")
    if not SHA256.fullmatch(sha):
        errors.append(f"surface row has invalid sha256: {row.get('path')}: {sha}")
    for rid in row.get("semantic_record_ids", "").split(";"):
        rid = rid.strip()
        if rid and rid != "n/a" and rid not in ids:
            errors.append(f"surface row references unknown adoption record: {row.get('path')}: {rid}")


expected_synthesis_ids = {f"SB-{i:03d}" for i in range(1, 11)}
synthesis_ids = {row.get("decision_id", "") for row in synthesis}
if synthesis_ids != expected_synthesis_ids or len(synthesis) != 10:
    errors.append(f"split-brain synthesis must contain exactly SB-001..SB-010, got {sorted(synthesis_ids)}")
try:
    with BASELINE.open(newline="", encoding="utf-8") as handle:
        baseline_rows = {row["path"]: row for row in csv.DictReader(handle, delimiter="\t")}
except (OSError, csv.Error) as exc:
    errors.append(f"invalid topology baseline for synthesis validation: {exc}")
    baseline_rows = {}
for row in synthesis:
    rid = row.get("decision_id", "")
    path = row.get("baseline_path", "")
    baseline = baseline_rows.get(path)
    if baseline is None:
        errors.append(f"split-brain synthesis references unknown baseline path: {rid}: {path}")
    elif row.get("baseline_sha256") != baseline.get("sha256"):
        errors.append(f"split-brain synthesis SHA mismatch: {rid}: {path}")
    if rid not in ids:
        errors.append(f"split-brain synthesis lacks adoption record: {rid}")
    if not any(rid in {x.strip() for x in surface.get("semantic_record_ids", "").split(";")} for surface in surfaces):
        errors.append(f"split-brain synthesis lacks surface evidence row: {rid}")
    if row.get("validation_status") not in ALLOWED_VALIDATION:
        errors.append(f"split-brain synthesis has invalid validation status: {rid}: {row.get('validation_status')}")

residual_classes = {row.get("class", "") for row in residuals}
missing_classes = sorted(REQUIRED_RESIDUAL_CLASSES - residual_classes)
extra_blank = any(not row.get("disposition") or not row.get("status") for row in residuals)
if missing_classes:
    errors.append(f"residual classification missing classes: {missing_classes}")
if extra_blank:
    errors.append("residual classification contains blank disposition/status")
if any(row.get("status") in {"pending", "unverified"} for row in residuals):
    errors.append("residual classification contains unresolved pending/unverified class")

archive_retirements = [row for row in retirements if row.get("object_class") == "refactor-source-archive"]
if len(archive_retirements) != 47:
    errors.append(f"retirement register must contain 47 refactor-source-archive records, found {len(archive_retirements)}")

print(
    f"adoption_records={len(ledger)} surface_records={len(surfaces)} "
    f"residual_classes={len(residuals)} archive_retirements={len(archive_retirements)} errors={len(errors)}"
)
for item in errors:
    print(f"ERROR: {item}")
sys.exit(1 if errors else 0)
