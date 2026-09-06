#!/usr/bin/env python3
"""Strict post-refactor-222 evidence-graph verifier.

Validates the current donor denominator, exact archive-backed surface hashes,
semantic backlinks, symbol backlinks, target/predecessor evidence, ledger graph,
and summary/cross-wave/universe denominators. It intentionally treats LumiNet
baseline/current records as target evidence rather than donor surfaces.
"""
from __future__ import annotations
import csv
import hashlib
import json
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT.parents[1]
BASELINE = WORK / "baseline221" / "LumiNet"
DATA = Path("/mnt/data")
GOV = ROOT / "governance" / "convergence"

LEDGER = GOV / "post-refactor-222-adoption-ledger.csv"
SURFACES = GOV / "post-refactor-222-surface-accountability.csv"
SYMBOLS = GOV / "post-refactor-222-symbols.csv"
CROSS = GOV / "post-refactor-222-cross-wave-accountability.csv"
UNIVERSE = GOV / "post-refactor-222-universe-accountability.csv"
ARCHIVES = GOV / "post-refactor-222-archive-accountability.csv"
SUMMARY = GOV / "post-refactor-222-summary.json"

REQUIRED_LEDGER = [
    "record_id","parent_record_id","composition_group_id","donor","domain","value_unit",
    "source_granularity","value_form","separability","donor_path","donor_sha256","donor_symbol",
    "transformation","mapping_topology","disposition","decision_rationale","target_capability",
    "target_nodes","invariant","negative_invariant","test_node","operator_surface","migration_impact",
    "license_note","risk_tier","dependency_record_ids","evidence_confidence","validation_status",
]
ALLOWED_DISP = {"adopted","adapted","hardened","extracted","recomposed","synthesized","inspired-native","guardrail-derived","superseded","rejected-with-reason","reference-only"}
ALLOWED_RISK = {"critical","high","medium","low"}
ALLOWED_CONF = {"high","medium","low","unknown"}
ALLOWED_STATUS = {"verified","statically-validated","reviewed","inferred","unverified","pending"}
TARGET_EVIDENCE = {"LumiNet/baseline-221": BASELINE, "LumiNet/current": ROOT}

errors: list[str] = []

def fail(msg: str) -> None:
    errors.append(msg)

def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        return list(r), list(r.fieldnames or [])

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def split_ids(value: str):
    return [x for x in value.split(";") if x and x != "n/a"]

def check_target_nodes(record: dict[str, str], field: str) -> None:
    for node in split_ids(record[field]):
        path = node.split("#", 1)[0]
        if not (ROOT / path).exists():
            fail(f"{record['record_id']}: missing {field} path {path}")

ledger, ledger_header = read_csv(LEDGER)
surfaces, _ = read_csv(SURFACES)
symbols, _ = read_csv(SYMBOLS)
cross, _ = read_csv(CROSS)
universe, _ = read_csv(UNIVERSE)
archives, _ = read_csv(ARCHIVES)
summary = json.loads(SUMMARY.read_text(encoding="utf-8"))

if ledger_header != REQUIRED_LEDGER:
    fail("ledger header mismatch")

ids = [r["record_id"] for r in ledger]
idset = set(ids)
if len(ids) != len(idset):
    fail("duplicate ledger record_id")
ledger_by_id = {r["record_id"]: r for r in ledger}

# Structural ledger checks.
edges: dict[str, list[str]] = {rid: [] for rid in ids}
for r in ledger:
    rid = r["record_id"]
    if r["disposition"] not in ALLOWED_DISP: fail(f"{rid}: invalid disposition {r['disposition']}")
    if r["risk_tier"] not in ALLOWED_RISK: fail(f"{rid}: invalid risk {r['risk_tier']}")
    if r["evidence_confidence"] not in ALLOWED_CONF: fail(f"{rid}: invalid confidence {r['evidence_confidence']}")
    if r["validation_status"] not in ALLOWED_STATUS: fail(f"{rid}: invalid validation status {r['validation_status']}")
    if len(r["donor_sha256"]) != 64 or any(c not in "0123456789abcdef" for c in r["donor_sha256"]):
        fail(f"{rid}: invalid donor_sha256")
    parent = r["parent_record_id"]
    if parent != "n/a":
        if parent not in idset: fail(f"{rid}: missing parent {parent}")
        else: edges[rid].append(parent)
    for dep in split_ids(r["dependency_record_ids"]):
        if dep not in idset: fail(f"{rid}: missing dependency {dep}")
        else: edges[rid].append(dep)
    check_target_nodes(r, "target_nodes")
    check_target_nodes(r, "test_node")
    if r["risk_tier"] in {"critical", "high"} and r["disposition"] != "reference-only":
        if r["invariant"] == "n/a" or r["negative_invariant"] == "n/a":
            fail(f"{rid}: high-risk material record lacks explicit invariant/negative invariant")
        if r["test_node"] == "n/a":
            fail(f"{rid}: high-risk material record lacks acceptance evidence")

# DAG check for parent+dependency graph.
visiting: set[str] = set(); done: set[str] = set()
def visit(n: str):
    if n in done: return
    if n in visiting:
        fail(f"ledger graph cycle at {n}")
        return
    visiting.add(n)
    for m in edges[n]: visit(m)
    visiting.remove(n); done.add(n)
for rid in ids: visit(rid)

# Current donor surfaces: every row linked, every link same donor, exact bytes from original ZIP.
surface_key: dict[tuple[str,str], dict[str,str]] = {}
surface_counts = Counter()
surface_links = defaultdict(set)
archive_handles: dict[str, zipfile.ZipFile] = {}
try:
    for s in surfaces:
        key = (s["donor"], s["path"])
        if key in surface_key: fail(f"duplicate surface {key}")
        surface_key[key] = s
        surface_counts[s["donor"]] += 1
        links = split_ids(s["semantic_record_ids"])
        if not links: fail(f"unlinked surface {s['donor']}:{s['path']}")
        for rid in links:
            if rid not in idset:
                fail(f"surface {s['donor']}:{s['path']} references unknown {rid}")
            elif ledger_by_id[rid]["donor"] != s["donor"]:
                fail(f"surface {s['donor']}:{s['path']} cross-donor link {rid}")
            else:
                surface_links[rid].add(key)
        archive = DATA / s["donor"]
        if not archive.exists():
            fail(f"missing original donor archive {archive}")
            continue
        zf = archive_handles.get(s["donor"])
        if zf is None:
            try:
                zf = zipfile.ZipFile(archive)
                archive_handles[s["donor"]] = zf
            except Exception as exc:
                fail(f"cannot open {archive.name}: {exc}")
                continue
        try:
            data = zf.read(s["path"])
        except Exception as exc:
            fail(f"archive member resolution failed {s['donor']}:{s['path']}: {exc}")
            continue
        if sha(data) != s["sha256"]:
            fail(f"surface hash mismatch {s['donor']}:{s['path']}")
finally:
    for zf in archive_handles.values(): zf.close()

# Ledger provenance must backlink either donor surfaces or exact target/predecessor source.
for r in ledger:
    donor = r["donor"]
    key = (donor, r["donor_path"])
    if donor in TARGET_EVIDENCE:
        p = TARGET_EVIDENCE[donor] / r["donor_path"]
        if not p.exists(): fail(f"{r['record_id']}: missing target evidence {p}")
        elif sha(p.read_bytes()) != r["donor_sha256"]: fail(f"{r['record_id']}: target evidence hash mismatch")
    else:
        s = surface_key.get(key)
        if s is None: fail(f"{r['record_id']}: donor path absent from surface matrix")
        elif s["sha256"] != r["donor_sha256"]: fail(f"{r['record_id']}: ledger/surface hash mismatch")
        elif key not in surface_links[r["record_id"]]: fail(f"{r['record_id']}: donor evidence is not bidirectionally linked")

# Symbol accountability: exact source hash + semantic links consistent with the containing surface.
seen_symbols = set()
for row in symbols:
    sig = (row["donor"], row["path"], row["symbol"], row["line"], row["snippet"])
    if sig in seen_symbols: fail(f"duplicate symbol inventory row {sig[:4]}")
    seen_symbols.add(sig)
    s = surface_key.get((row["donor"], row["path"]))
    if s is None:
        fail(f"symbol missing source surface {row['donor']}:{row['path']}")
        continue
    if row["sha256"] != s["sha256"]: fail(f"symbol/source hash drift {row['donor']}:{row['path']}:{row['symbol']}")
    slinks = set(split_ids(row["semantic_record_ids"]))
    if not slinks: fail(f"unlinked symbol {row['donor']}:{row['path']}:{row['symbol']}")
    if not slinks.issubset(set(split_ids(s["semantic_record_ids"]))):
        fail(f"symbol links escape containing surface semantics {row['donor']}:{row['path']}:{row['symbol']}")

# Cross-wave donor denominators and archive identities.
cross_donors = {r["project"]: r for r in cross if r["role"] == "donor"}
if set(cross_donors) != set(surface_counts):
    fail(f"cross-wave donor set drift: cross={len(cross_donors)} surfaces={len(surface_counts)}")
for donor, count in surface_counts.items():
    r = cross_donors[donor]
    if int(r["surface_count"]) != count: fail(f"{donor}: cross-wave surface count drift")
    if int(r["exact_historical_matches"]) + int(r["reopened_surfaces"]) != count:
        fail(f"{donor}: historical+reopened denominator mismatch")
    archive = DATA / donor
    if sha(archive.read_bytes()) != r["archive_sha256"]: fail(f"{donor}: archive hash drift")
    for rid in split_ids(r["root_record_ids"]):
        if rid not in idset or ledger_by_id[rid]["donor"] != donor: fail(f"{donor}: invalid root record {rid}")

# Archive-accountability identities, including duplicate aliases and the frozen baseline artifact.
for a in archives:
    p = DATA / a["archive"]
    if not p.exists():
        fail(f"archive-accountability path missing {a['archive']}")
        continue
    if sha(p.read_bytes()) != a["sha256"]: fail(f"archive-accountability hash drift {a['archive']}")
    if a["duplicate_of"] != "n/a":
        canonical = DATA / a["duplicate_of"]
        if not canonical.exists() or sha(canonical.read_bytes()) != a["sha256"]:
            fail(f"duplicate alias mismatch {a['archive']} -> {a['duplicate_of']}")

# Summary denominators must be derivable, not hand-maintained claims.
disp = Counter(r["disposition"] for r in ledger)
if summary["semantic_records"] != len(ledger): fail("summary semantic_records drift")
if summary["current_donor_surfaces"] != len(surfaces): fail("summary current_donor_surfaces drift")
if summary["current_donor_symbols"] != len(symbols): fail("summary current_donor_symbols drift")
if summary["unique_current_donors"] != len(surface_counts): fail("summary unique_current_donors drift")
if summary["dispositions"] != dict(sorted(disp.items())): fail("summary dispositions drift")
if summary["historically_exact_surfaces"] + summary["reopened_surfaces"] != len(surfaces): fail("summary historical denominator drift")

# Universe must contain exactly one target + 62 donor project rows for the accumulated waves.
roles = Counter(r["role"] for r in universe)
if roles.get("target") != 1: fail(f"universe target count {roles.get('target', 0)} != 1")
if roles.get("donor") != 62: fail(f"universe donor count {roles.get('donor', 0)} != 62")
current_universe = {r["project"] for r in universe if r["wave"] == "post-refactor-222" and r["role"] == "donor"}
# Universe stores project names without archive extensions/duplicate suffixes; compare normalized labels.
def norm(name: str) -> str:
    return name[:-4] if name.endswith(".zip") else name
if current_universe != {norm(x) for x in surface_counts}:
    fail("universe current-donor set drift")
for row in universe:
    if row["wave"] != "post-refactor-222" or row["role"] != "donor":
        continue
    expected_donor = next((d for d in surface_counts if norm(d) == row["project"]), None)
    if expected_donor is None:
        fail(f"universe current project lacks donor archive: {row['project']}")
        continue
    for rid in split_ids(row["evidence_records"]):
        if rid not in idset or ledger_by_id[rid]["donor"] != expected_donor:
            fail(f"universe current project has invalid evidence record {row['project']}:{rid}")

if errors:
    for e in errors[:200]: print("FAIL:", e)
    if len(errors) > 200: print(f"... {len(errors)-200} more failures")
    sys.exit(1)
print(
    "post-refactor-222 evidence graph: VERIFIED | "
    f"ledger={len(ledger)} surfaces={len(surfaces)} symbols={len(symbols)} "
    f"current_donors={len(surface_counts)} accumulated_donors={roles['donor']}"
)
