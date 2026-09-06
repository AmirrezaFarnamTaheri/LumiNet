#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
G = ROOT / "governance" / "convergence"
A = ROOT / "governance" / "audit"
P = "post-refactor-83"
DELTA_REL = f"governance/convergence/{P}-target-delta.csv"
EXPECTED = {
    "new_donors": 20,
    "outer_members": 456,
    "surfaces": 352,
    "directories": 104,
    "modules": 53,
    "symbols": 1646,
    "ledger": 83,
    "semantics": 30,
    "supersession": 19,
    "repairs": 6,
    "planes": 12,
    "historical_donors": 63,
    "cumulative_donors": 83,
    "baseline": 2596,
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VALID_DISPOSITIONS = {
    "adopted", "adapted", "hardened", "extracted", "recomposed", "synthesized",
    "inspired-native", "guardrail-derived", "superseded", "rejected-with-reason", "reference-only",
}
VALID_STATUS = {"verified", "statically-validated", "reviewed", "inferred", "unverified", "pending"}


def read_csv(name: str):
    p = G / name
    if not p.is_file():
        raise AssertionError(f"missing {p.relative_to(ROOT)}")
    with p.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def digest(p: Path):
    if p.is_symlink():
        t = os.readlink(p)
        return ("symlink", hashlib.sha256(t.encode()).hexdigest(), t)
    return ("file", hashlib.sha256(p.read_bytes()).hexdigest(), "n/a")


def scan_current():
    out = {}
    for p in sorted(ROOT.rglob("*")):
        if not (p.is_file() or p.is_symlink()):
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel == DELTA_REL or rel.startswith(".git/") or "/__pycache__/" in "/" + rel or rel.endswith(".pyc"):
            continue
        out[rel] = digest(p)
    return out


def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


def require(errors: list[str], condition: bool, message: str):
    if not condition:
        errors.append(message)


def anchor_exists(node: str) -> bool:
    node = (node or "").strip()
    if not node or node == "n/a":
        return True
    if "#" not in node:
        return (ROOT / node).is_file()
    rel, anchor = node.split("#", 1)
    p = ROOT / rel
    if not p.is_file():
        return False
    raw = p.read_text(encoding="utf-8", errors="replace")
    candidates = {anchor, anchor.split(".")[-1], anchor.replace("-", "_"), anchor.replace("-", " ")}
    return any(c and re.search(r"(?<![A-Za-z0-9_])" + re.escape(c) + r"(?![A-Za-z0-9_])", raw, re.I) for c in candidates)


def main() -> int:
    errors: list[str] = []
    try:
        donors = read_csv(f"{P}-donors.csv")
        surfaces = read_csv(f"{P}-surfaces.csv")
        dirs = read_csv(f"{P}-directories.csv")
        modules = read_csv(f"{P}-modules.csv")
        symbols = read_csv(f"{P}-symbols.csv")
        ledger = read_csv(f"{P}-adoption-ledger.csv")
        historical = read_csv(f"{P}-historical-evidence.csv")
        nested = read_csv(f"{P}-nested-archives.csv")
        sups = read_csv(f"{P}-supersession-map.csv")
        repairs = read_csv(f"{P}-target-repairs.csv")
        planes = read_csv(f"{P}-high-level-plane-audit.csv")
        baseline_rows = read_csv(f"{P}-baseline-files.csv")
        delta_rows = read_csv(f"{P}-target-delta.csv")
        license_rows = read_csv(f"{P}-license-map.csv")
    except Exception as exc:
        print("post-refactor-83 convergence:", exc)
        return 1

    counts = {
        "new_donors": len(donors), "surfaces": len(surfaces), "directories": len(dirs),
        "modules": len(modules), "symbols": len(symbols), "ledger": len(ledger),
        "supersession": len(sups), "repairs": len(repairs), "planes": len(planes),
        "baseline": len(baseline_rows),
    }
    for key, actual in counts.items():
        require(errors, actual == EXPECTED[key], f"{key} count {actual} != {EXPECTED[key]}")
    semantics = [r for r in ledger if r.get("record_id", "").startswith("PR83-S")]
    require(errors, len(semantics) == EXPECTED["semantics"], f"semantic count {len(semantics)} != {EXPECTED['semantics']}")
    require(errors, sum(int(r["member_count"]) for r in donors) == EXPECTED["outer_members"], "outer archive member denominator mismatch")
    require(errors, sum(int(r["file_surfaces"]) for r in donors) == EXPECTED["surfaces"], "surface rollup mismatch")
    require(errors, sum(int(r["directories"]) for r in donors) == EXPECTED["directories"], "directory rollup mismatch")
    require(errors, sum(int(r["symbols"]) for r in donors) == EXPECTED["symbols"], "symbol rollup mismatch")
    require(errors, len(license_rows) == EXPECTED["new_donors"], "license-map donor count mismatch")

    # Historical evidence is immutable and hash-bound.
    for row in historical:
        p = G / row["artifact"]
        require(errors, p.is_file(), f"historical artifact missing: {row['artifact']}")
        if p.is_file():
            require(errors, hashlib.sha256(p.read_bytes()).hexdigest() == row["sha256"], f"historical artifact hash drift: {row['artifact']}")
    ultimate_donors = read_csv("ultimate-pass-donors.csv")
    require(errors, len(ultimate_donors) == EXPECTED["historical_donors"], "historical donor count drift")
    require(errors, len(ultimate_donors) + len(donors) == EXPECTED["cumulative_donors"], "cumulative donor count mismatch")

    # Every surface and bounded module is independently accountable.
    ledger_ids = {r["record_id"] for r in ledger}
    module_ids = {r["module_id"] for r in modules}
    require(errors, len(ledger_ids) == len(ledger), "duplicate ledger record ids")
    require(errors, len(module_ids) == len(modules), "duplicate module ids")
    surface_keys = set()
    for row in surfaces:
        key = (row["donor"], row["path"])
        require(errors, key not in surface_keys, f"duplicate surface {key}")
        surface_keys.add(key)
        require(errors, bool(HEX64.fullmatch(row.get("sha256", ""))), f"surface {key}: invalid sha256")
        refs = [x for x in row.get("semantic_record_ids", "").split(";") if x]
        require(errors, bool(refs), f"surface {key}: no accountability record")
        for rid in refs:
            require(errors, rid in ledger_ids, f"surface {key}: unknown record {rid}")
    for row in modules:
        require(errors, 0 < int(row["surface_count"]) <= 100, f"module {row['module_id']}: invalid surface bound")
        key = (row["donor"], row["representative_path"])
        require(errors, key in surface_keys, f"module {row['module_id']}: missing representative surface")
        sr = next((s for s in surfaces if (s["donor"], s["path"]) == key), None)
        if sr:
            require(errors, sr["sha256"] == row["representative_sha256"], f"module {row['module_id']}: representative hash mismatch")
    for row in semantics:
        key = (row["donor"], row["donor_path"])
        require(errors, key in surface_keys, f"semantic {row['record_id']}: donor surface missing")
        sr = next((s for s in surfaces if (s["donor"], s["path"]) == key), None)
        if sr:
            require(errors, row["donor_sha256"] == sr["sha256"], f"semantic {row['record_id']}: donor hash mismatch")
        require(errors, row.get("disposition") in VALID_DISPOSITIONS, f"semantic {row['record_id']}: invalid disposition")
        require(errors, row.get("validation_status") in VALID_STATUS, f"semantic {row['record_id']}: invalid validation status")
        for node in [x for x in row.get("target_nodes", "").split(";") if x and x != "n/a"]:
            require(errors, anchor_exists(node), f"semantic {row['record_id']}: target anchor missing {node}")
        test_node = row.get("test_node", "")
        if test_node and test_node != "n/a":
            require(errors, anchor_exists(test_node), f"semantic {row['record_id']}: test anchor missing {test_node}")

    # Duplicate/nested archives are explicitly proven, never double-counted as semantics.
    require(errors, len(nested) == 4, f"nested/duplicate archive evidence count {len(nested)} != 4")
    for row in nested:
        require(errors, row.get("identical_prior") == "yes", f"nested/duplicate provenance is not exact: {row.get('nested_archive')}")
        require(errors, row.get("sha256") == row.get("prior_sha256"), f"nested/duplicate hash mismatch: {row.get('nested_archive')}")

    # Exact successor delta from refactor-audited baseline.
    baseline = {}
    for row in baseline_rows:
        path = row["path"].strip()
        require(errors, path not in baseline, f"duplicate baseline path {path}")
        baseline[path] = (row["file_type"], row["sha256"], row["link_target"])
    successor_baseline_path = G / "post-refactor-97-baseline-files.csv"
    if successor_baseline_path.is_file():
        with successor_baseline_path.open(encoding="utf-8-sig", newline="") as f:
            successor_baseline_rows = list(csv.DictReader(f))
        current = {
            row["path"].strip(): (row["file_type"], row["sha256"], row["link_target"])
            for row in successor_baseline_rows
            if row["path"].strip() != DELTA_REL
        }
        require(errors, len(current) == len(successor_baseline_rows) - 1, "duplicate successor-baseline paths or missing historical self-delta")
    else:
        current = scan_current()
    expected_delta = {}
    for path in sorted(set(baseline) | set(current)):
        before, after = baseline.get(path), current.get(path)
        if before == after:
            continue
        if before is None:
            expected_delta[path] = ("added", "n/a", after[1])
        elif after is None:
            expected_delta[path] = ("deleted", before[1], "n/a")
        else:
            expected_delta[path] = ("modified", before[1], after[1])
    delta = {}
    for row in delta_rows:
        path = row["path"].strip()
        require(errors, path and path not in delta, f"duplicate/empty target delta path {path!r}")
        delta[path] = row
        exp = expected_delta.get(path)
        if exp is None:
            errors.append(f"target delta {path}: not changed")
            continue
        got = (row["change_type"], row["baseline_sha256"], row["current_sha256"])
        require(errors, got == exp, f"target delta {path}: mismatch got={got} expected={exp}")
        require(errors, bool(row.get("reason", "").strip()), f"target delta {path}: missing reason")
    missing = sorted(set(expected_delta) - set(delta))
    extra = sorted(set(delta) - set(expected_delta))
    if missing:
        errors.append(f"target delta missing {len(missing)} paths: {missing[:100]}")
    if extra:
        errors.append(f"target delta extra {len(extra)} paths: {extra[:100]}")

    # F-014--F-018 closure invariants.
    closure = A / "f14-f18-closure.csv"
    require(errors, closure.is_file(), "F-014--F-018 closure ledger missing")
    if closure.is_file():
        with closure.open(encoding="utf-8-sig", newline="") as f:
            crows = {r["finding"]: r for r in csv.DictReader(f)}
        for fid in [f"F-{n:03d}" for n in range(14, 19)]:
            require(errors, fid in crows, f"closure ledger missing {fid}")
        for fid in ["F-014", "F-015", "F-016", "F-018"]:
            require(errors, crows.get(fid, {}).get("status") == "verified", f"{fid} not verified in closure ledger")
        require(errors, crows.get("F-017", {}).get("confidence") == "statically-validated", "F-017 must retain static-only Rust claim boundary")

    provision = text("src/apps/daemon/internal/integrations/provision/vps.go")
    ssh_tunnel = text("src/apps/daemon/internal/runtime/proxy/ssh_tunnel.go")
    sshtrust = text("src/apps/daemon/internal/platform/sshtrust/host_identity.go")
    require(errors, "ssh.InsecureIgnoreHostKey()" not in provision and "ssh.InsecureIgnoreHostKey()" not in ssh_tunnel, "live SSH host-key bypass returned")
    for marker in ["ParseSHA256", "FingerprintSHA256", "subtle.ConstantTimeCompare"]:
        require(errors, marker in sshtrust, f"SSH host identity invariant missing {marker}")
    require(errors, "get.docker.com" not in provision, "mutable remote Docker bootstrap returned")
    for marker in ["apt-cache policy docker.io", "docker.io=", "aptCandidateVersion"]:
        require(errors, marker in provision, f"trusted package bootstrap invariant missing {marker}")

    rust_checker = text("scripts/checks/check_rust_ffi_refactor.py")
    require(errors, "legacy/native C ABI changed" in rust_checker and "c_str_to_str" in rust_checker, "Rust FFI successor checker incomplete")
    require(errors, "check_rust_ffi_refactor.py" in text("Makefile"), "verify-repo does not execute Rust FFI successor checker")

    relay = text("src/apps/daemon/internal/integrations/relayclient/relay_conn_state.go")
    relay_tests = text("src/apps/daemon/internal/integrations/relayclient/relay_conn_state_test.go")
    for marker in ["maxRelayQueuedWriteBytes", "SetReadDeadline", "SetWriteDeadline", "RecordPollFailure", "waitRelayRetry"]:
        require(errors, marker in relay, f"relay deep-state invariant missing {marker}")
    for marker in ["TestRelayPollFailureBackoffIsBoundedAndResets", "TestWaitRelayRetryHonorsCancellation"]:
        require(errors, marker in relay_tests, f"relay backoff regression missing {marker}")

    # New donor-derived repairs and negative guardrails.
    pool = text("src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go")
    pool_tests = text("src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan_test.go")
    require(errors, "attempts > 0" in pool and "o.Successes > 0" in pool, "endpoint pool still admits unobserved/never-successful endpoint")
    require(errors, "TestBuildEndpointPoolPlanDoesNotDispatchUnobservedOrNeverSuccessfulEndpoints" in pool_tests, "endpoint admission regression missing")
    resolver = text("src/apps/daemon/internal/networking/dns/resolver.go")
    require(errors, "InsecureSkipVerify" not in resolver or "false" in resolver, "encrypted DNS privacy trust regressed")
    host_ownership = text("scripts/checks/check_host_network_ownership.py")
    require(errors, "ApplyHostNetwork" in host_ownership or "RecoverHostNetworkInDir" in host_ownership, "host-network single-authority guardrail missing")

    # Historical layering and verify-repo wiring.
    refactor_checker = text("scripts/checks/check_refactor_audit.py")
    require(errors, 'SUCCESSOR_BASELINE = G / "post-refactor-83-baseline-files.csv"' in refactor_checker, "historical refactor checker lacks successor baseline")
    makefile = text("Makefile")
    require(errors, "check_post_refactor_83_convergence.py" in makefile, "verify-repo does not execute post-refactor-83 gate")
    if successor_baseline_path.is_file():
        require(errors, "post-refactor-97-baseline-files.csv" in text("scripts/checks/check_post_refactor_83_convergence.py"), "post-refactor-83 gate does not freeze itself at the successor baseline")

    if errors:
        print(f"post-refactor-83 convergence: donors={len(donors)} members={EXPECTED['outer_members']} surfaces={len(surfaces)} directories={len(dirs)} modules={len(modules)} symbols={len(symbols)} semantics={len(semantics)} records={len(ledger)} changes={len(delta_rows)} errors={len(errors)}")
        for error in errors[:400]:
            print("ERROR:", error)
        return 1
    print(f"post-refactor-83 convergence: donors={len(donors)} cumulative_donors={EXPECTED['cumulative_donors']} members={EXPECTED['outer_members']} surfaces={len(surfaces)} directories={len(dirs)} modules={len(modules)} symbols={len(symbols)} semantics={len(semantics)} records={len(ledger)} supersession={len(sups)} repairs={len(repairs)} changes={len(delta_rows)} errors=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
