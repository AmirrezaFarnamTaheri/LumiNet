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
BASELINE = G / "refactor-pass-baseline-files.csv"
DELTA = G / "refactor-pass-target-delta.csv"
DELTA_REL = DELTA.relative_to(ROOT).as_posix()
SUCCESSOR_BASELINE = G / "post-refactor-83-baseline-files.csv"
EXPECTED = {"baseline": 2588, "findings": 18, "coverage": 15, "remediations": 13}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def rows(path: Path):
    if not path.is_file():
        raise AssertionError(f"missing {path.relative_to(ROOT)}")
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def digest(path: Path):
    if path.is_symlink():
        target = os.readlink(path)
        return ("symlink", hashlib.sha256(target.encode()).hexdigest(), target)
    return ("file", hashlib.sha256(path.read_bytes()).hexdigest(), "n/a")


def scan_current():
    # Once a successor convergence pass exists, validate the frozen refactor state
    # against that successor baseline. Later repairs must not rewrite refactor history.
    if SUCCESSOR_BASELINE.is_file():
        out = {}
        with SUCCESSOR_BASELINE.open(encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                rel = row["path"].strip()
                if rel == DELTA_REL:
                    continue
                out[rel] = (row["file_type"].strip(), row["sha256"].strip(), row["link_target"])
        return out
    out = {}
    for path in sorted(ROOT.rglob("*")):
        if not (path.is_file() or path.is_symlink()):
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel == DELTA_REL or rel.startswith(".git/") or "/__pycache__/" in "/" + rel or rel.endswith(".pyc"):
            continue
        out[rel] = digest(path)
    return out


def text(rel: str):
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


def require(errors: list[str], condition: bool, message: str):
    if not condition:
        errors.append(message)


def main() -> int:
    errors: list[str] = []
    try:
        baseline_rows = rows(BASELINE)
        delta_rows = rows(DELTA)
        finding_rows = rows(A / "refactor-pass-findings.csv")
        coverage_rows = rows(A / "refactor-pass-coverage.csv")
        remediation_rows = rows(A / "refactor-pass-remediation.csv")
    except Exception as exc:
        print("refactor audit:", exc)
        return 1

    require(errors, len(baseline_rows) == EXPECTED["baseline"], f"baseline rows {len(baseline_rows)} != {EXPECTED['baseline']}")
    require(errors, len(finding_rows) == EXPECTED["findings"], f"finding rows {len(finding_rows)} != {EXPECTED['findings']}")
    require(errors, len(coverage_rows) == EXPECTED["coverage"], f"coverage rows {len(coverage_rows)} != {EXPECTED['coverage']}")
    require(errors, len(remediation_rows) == EXPECTED["remediations"], f"remediation rows {len(remediation_rows)} != {EXPECTED['remediations']}")

    baseline = {}
    for row in baseline_rows:
        path = row.get("path", "").strip()
        if not path or path in baseline:
            errors.append(f"duplicate/empty baseline path {path!r}")
            continue
        if not HEX64.fullmatch(row.get("sha256", "")):
            errors.append(f"baseline {path}: invalid sha256")
        baseline[path] = (row["file_type"], row["sha256"], row["link_target"])

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
        path = row.get("path", "").strip()
        if not path or path in delta:
            errors.append(f"duplicate/empty refactor delta path {path!r}")
            continue
        delta[path] = row
        exp = expected_delta.get(path)
        if exp is None:
            errors.append(f"refactor delta {path}: not changed")
            continue
        got = (row.get("change_type"), row.get("baseline_sha256"), row.get("current_sha256"))
        if got != exp:
            errors.append(f"refactor delta {path}: mismatch got={got} expected={exp}")
        if not row.get("finding_ids", "").strip() or not row.get("reason", "").strip():
            errors.append(f"refactor delta {path}: incomplete accountability")
    missing = sorted(set(expected_delta) - set(delta))
    extra = sorted(set(delta) - set(expected_delta))
    if missing:
        errors.append(f"refactor target delta missing {len(missing)} paths: {missing[:80]}")
    if extra:
        errors.append(f"refactor target delta extra {len(extra)} paths: {extra[:80]}")

    findings = {row["id"]: row for row in finding_rows}
    require(errors, len(findings) == len(finding_rows), "duplicate finding ids")
    for fid in [f"F-{n:03d}" for n in range(1, 19)]:
        require(errors, fid in findings, f"missing finding {fid}")
    for fid in ["F-015", "F-016", "F-017", "F-018"]:
        require(errors, findings.get(fid, {}).get("priority") == "Design first", f"{fid}: unresolved risk not marked Design first")
    require(errors, findings.get("F-017", {}).get("confidence") == "Statically validated", "F-017 Rust FFI evidence must not claim execution")

    coverage_ids = {row.get("id") for row in coverage_rows}
    require(errors, len(coverage_ids) == len(coverage_rows), "duplicate coverage ids")
    require(errors, any(row.get("status") == "Blocked" and "Rust" in row.get("surface", "") for row in coverage_rows), "Rust execution blocker missing from coverage ledger")

    provision = text("src/apps/daemon/internal/integrations/provision/provision.go")
    runners = text("src/apps/daemon/internal/workflows/jobs/runners_provision.go")
    vps = text("src/apps/daemon/internal/integrations/provision/vps.go")
    require(errors, "Subscribe(" not in provision and "chans" not in provision, "ProvisionLogger subscriber lifecycle still present")
    require(errors, ".Subscribe()" not in runners, "provision job runner still depends on logger subscription")
    for marker in ["maxSSHCommandOutput", "boundedCapture", 'fmt.Errorf("remote command failed: %w", err)']:
        require(errors, marker in vps, f"provision SSH bound/redaction invariant missing {marker}")

    manager = text("src/apps/daemon/internal/runtime/runtimecore/manager.go")
    manager_tests = text("src/apps/daemon/internal/runtime/runtimecore/manager_test.go")
    for marker in ["startEngineLocked", "restorePreviousLocked", "errors.Join"]:
        require(errors, marker in manager, f"runtime replacement invariant missing {marker}")
    for marker in ["TestManagerRestoresPreviousConfigurationWhenReplacementStartFails", "TestManagerReportsReplacementAndRollbackFailure"]:
        require(errors, marker in manager_tests, f"runtime replacement regression missing {marker}")

    config = text("src/apps/daemon/internal/foundation/config/config.go")
    require(errors, not re.search(r"(?m)^func \(m \*Manager\) Save\(", config), "unconditional config Manager.Save still exported")
    require(errors, "GetCopy(" not in config, "duplicate config GetCopy still exported")
    for marker in ["GetWithRevision", "SaveIfRevision", "ErrRevisionConflict"]:
        require(errors, marker in config, f"config CAS interface missing {marker}")

    dns = text("src/apps/daemon/internal/networking/dns/doh_resolver.go")
    retired_dns = [
        "GetResolverVersion", "SetResolverVersion", "ResetResolverPreset", "VerifyResolverPreset",
        "GetSuccessCount", "GetFailureCount", "IncrementSuccess", "IncrementFailure", "ResetStats", "GetStatsMap",
        "ExportResolverConfigJSON", "ImportResolverConfigJSON", "SetSingleflight", "GetSingleflight",
        "RemoveProvider", "GetProviders", "GetProvidersCount", "GetCacheKeys", "IsCached", "GetCachedIPs", "RemoveCacheKey",
        "GetGeoIPService", "SetGeoIPService", "SetProviderWeight", "GetProviderWeight", "SetProviderBypass", "GetProviderBypass",
        "GetActiveProvidersCount", "HasProvider", "GetProvidersNames", "GetProvidersURLs", "GetTTLSeconds", "SetTTLSeconds",
        "GetCacheExpiredCount", "ClearExpiredCache", "GetIPCountryCode", "IsIPInCountry", "ValidateHostname",
    ]
    for symbol in retired_dns:
        require(errors, not re.search(rf"(?m)^func \(r \*FailoverDOHResolver\) {re.escape(symbol)}\b", dns), f"dead DNS interface returned: {symbol}")

    for rel in [
        "src/apps/daemon/internal/platform/system/admin_ssh.go",
        "src/apps/daemon/internal/platform/system/tproxy_linux.go",
        "src/apps/daemon/internal/workflows/jobs/runner.go",
        "labs/daemon/modules/mobile/protect_unix.go",
    ]:
        require(errors, not (ROOT / rel).exists(), f"retired dormant module returned: {rel}")

    gsa = text("src/apps/daemon/internal/integrations/relayclient/gsa_relay.go")
    wire = text("src/apps/daemon/internal/integrations/relayclient/relay_wire.go")
    wire_tests = text("src/apps/daemon/internal/integrations/relayclient/relay_wire_test.go")
    serverless = text("src/apps/daemon/internal/integrations/relayclient/serverless_dialer.go")
    require(errors, "type TunnelPayload = TunnelPayload" not in gsa and "type TunnelResponse = TunnelResponse" not in gsa, "GSA self aliases returned")
    if SUCCESSOR_BASELINE.is_file():
        state = text("src/apps/daemon/internal/integrations/relayclient/relay_conn_state.go")
        state_tests = text("src/apps/daemon/internal/integrations/relayclient/relay_conn_state_test.go")
        for marker in ["relayConnState", "maxRelayQueuedWriteBytes", "SetReadDeadline", "SetWriteDeadline"]:
            require(errors, marker in state, f"successor relay-state invariant missing {marker}")
        require(errors, "TestRelayConnState" in state_tests or "TestRelayPollFailureBackoff" in state_tests, "successor relay-state regressions missing")
    else:
        require(errors, "atomic.Bool" in gsa and "atomic.Bool" in serverless, "relay close state is not atomic")
        require(errors, "prependFailedWrite" in wire and "prependFailedWrite" in gsa and "prependFailedWrite" in serverless, "shared relay rollback primitive missing")
        require(errors, "TestPrependFailedWrite" in wire_tests, "relay rollback regression missing")
    require(errors, "InsecureSkipVerify: true" not in serverless, "live serverless relay still disables TLS verification")

    nat = text("src/apps/daemon/internal/platform/system/nat/packet_ip.go")
    require(errors, "ProtocolTCP" in nat and "ProtocolUDP" in nat, "NAT protocol constant rename missing")
    require(errors, not re.search(r"(?m)^\s*TCP\s*=\s*0x06", nat) and not re.search(r"(?m)^\s*UDP\s*=\s*0x11", nat), "NAT colliding protocol constants returned")

    wstunnel = text("src/apps/daemon/internal/runtime/proxy/wstunnel.go")
    wstunnel_tests = text("src/apps/daemon/internal/runtime/proxy/wstunnel_test.go")
    require(errors, "relayclient.WebSocketConn" in wstunnel and "serverless.WebSocketConn" not in wstunnel, "WebTunnel is not using canonical relay adapter")
    require(errors, "InsecureSkipVerify: strings.TrimSpace(pinnedFingerprint) != \"\"" in wstunnel, "WebTunnel PKI-or-explicit-pin invariant missing")
    require(errors, "TestStunnelRejectsUntrustedCertificateWithoutPin" in wstunnel_tests, "WebTunnel untrusted certificate regression missing")

    decl_checker = text("scripts/checks/check_go_declaration_integrity.go")
    makefile = text("Makefile")
    require(errors, "duplicate top-level" in decl_checker and "parser.ParseFile" in decl_checker, "Go declaration integrity checker is incomplete")
    require(errors, "check_go_declaration_integrity.go" in makefile, "verify-repo does not run Go declaration integrity checker")
    require(errors, "check_refactor_audit.py" in makefile, "verify-repo does not run refactor audit gate")

    ultimate = text("scripts/checks/check_ultimate_convergence.py")
    require(errors, "SUCCESSOR_BASELINE=G/'refactor-pass-baseline-files.csv'" in ultimate, "historical ultimate checker lacks refactor successor baseline")

    for rel in [
        "governance/audit/refactor-pass-audit.md",
        "governance/audit/refactor-pass-rust-ffi-rfc.md",
        "governance/audit/refactor-pass-refactor-plan.md",
        "governance/audit/refactor-pass-findings.csv",
        "governance/audit/refactor-pass-coverage.csv",
        "governance/audit/refactor-pass-remediation.csv",
        "governance/audit/refactor-pass-validation.md",
    ]:
        require(errors, (ROOT / rel).is_file(), f"missing durable audit artifact {rel}")

    # Known high risks remain visible in the historical refactor state. A successor
    # pass may close them, but must carry explicit closure evidence instead of
    # mutating historical findings.
    if SUCCESSOR_BASELINE.is_file():
        closure = A / "f14-f18-closure.csv"
        require(errors, closure.is_file(), "successor F-014--F-018 closure evidence missing")
        successor = ROOT / "scripts/checks/check_post_refactor_83_convergence.py"
        require(errors, successor.is_file(), "successor convergence checker missing")
    else:
        ssh_hits = []
        for rel in ["src/apps/daemon/internal/integrations/provision/vps.go", "src/apps/daemon/internal/runtime/proxy/ssh_tunnel.go"]:
            if "ssh.InsecureIgnoreHostKey()" in text(rel):
                ssh_hits.append(rel)
        require(errors, len(ssh_hits) == 2, f"SSH risk inventory drifted; expected two explicit unresolved host-key bypasses, got {ssh_hits}")
        require(errors, "curl -fsSL https://get.docker.com | sh" in vps, "bootstrap risk inventory drifted without a corresponding finding update")

    if errors:
        print(f"refactor audit: baseline={len(baseline_rows)} findings={len(finding_rows)} coverage={len(coverage_rows)} remediations={len(remediation_rows)} changes={len(delta_rows)} errors={len(errors)}")
        for error in errors[:300]:
            print("ERROR:", error)
        return 1
    print(f"refactor audit: baseline={len(baseline_rows)} findings={len(finding_rows)} coverage={len(coverage_rows)} remediations={len(remediation_rows)} changes={len(delta_rows)} errors=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
