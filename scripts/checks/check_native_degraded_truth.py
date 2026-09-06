#!/usr/bin/env python3
"""Guard capability truth for CGO-disabled/native-unlinked bridge builds."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
errors: list[str] = []


def text(path: str) -> str:
    p = ROOT / path
    if not p.exists():
        errors.append(f"missing required file: {path}")
        return ""
    return p.read_text(encoding="utf-8")


degraded = text("src/apps/daemon/internal/native/bridge/core_degraded.go")
version = text("src/apps/daemon/internal/native/bridge/version_degraded.go")
caps = text("src/apps/daemon/internal/adapters/api/handlers_capabilities.go")
test = text("src/apps/daemon/internal/native/bridge/core_degraded_truth_test.go")

if "return \"\", ErrNativeCoreUnavailable" not in version:
    errors.append("degraded NegotiateVersion does not fail closed")
if "!bridge.NativeCoreLinked" not in caps or "native core is not linked in this build" not in caps:
    errors.append("capability discovery does not expose native-core unavailability when native core is unlinked")

for forbidden in ('\"mock\": \"true\"', 'LatencyMs: 5.0', '{\"success\":true}'):
    if forbidden in degraded:
        errors.append(f"degraded bridge contains fabricated success marker: {forbidden}")

native_only = {
    "IcmpScan": "ErrNativeCoreUnavailable",
    "SniDetect": "ErrNativeCoreUnavailable",
    "SpeedTest": "ErrNativeCoreUnavailable",
    "WgProbe": "ErrNativeCoreUnavailable",
    "InjectFakePacket": "ErrNativeCoreUnavailable",
    "DisassemblePayload": "ErrNativeCoreUnavailable",
}
for name, required in native_only.items():
    match = re.search(rf"(?ms)^func {re.escape(name)}\b.*?\n\}}", degraded)
    if not match:
        errors.append(f"degraded bridge missing {name}")
    elif required not in match.group(0):
        errors.append(f"degraded {name} does not fail closed with {required}")

# Native-only raw injection must never silently succeed.
inject = re.search(r"(?ms)^func InjectFakePacket\b.*?\n\}", degraded)
if inject and re.search(r"(?m)^\s*return nil\s*$", inject.group(0)):
    errors.append("degraded InjectFakePacket still reports success")

retired_wrappers = (
    "Socks5Probe", "HttpGet", "ExpandTargets", "CaptivePortalProbe",
    "PadClientHello", "AnalyzeAnomaly", "OptimizeHosts", "PatchMemory",
    "DecryptCookies", "GetActiveConnections", "StartAdbForwarder",
    "RegisterSHM", "PushPacketSHM", "PopPacketSHM",
)
for name in retired_wrappers:
    if re.search(rf"(?m)^func {re.escape(name)}\b", degraded):
        errors.append(f"retired degraded Go bridge facade returned: {name}")
    real = text("src/apps/daemon/internal/native/bridge/core.go")
    if re.search(rf"(?m)^func {re.escape(name)}\b", real):
        errors.append(f"retired native Go bridge facade returned: {name}")

if "net.Resolver" not in degraded or "Dial:" not in degraded or ".DialContext(" not in degraded:
    errors.append("pure-Go DNS fallback does not route through caller-selected resolver")
if "TTL: 0" not in degraded:
    errors.append("pure-Go DNS fallback no longer preserves unknown TTL truth")
if "DoH DNS fallback" not in degraded or "DoT DNS fallback" not in degraded:
    errors.append("unsupported encrypted DNS fallback does not fail closed")

for test_name in (
    "TestNativeOnlyFallbacksFailClosed",
    "TestPureGoPortScanHandlesZeroConcurrency",
    "TestPureGoDNSFallbackUsesRequestedServer",
):
    if test_name not in test:
        errors.append(f"missing degraded bridge truth regression test: {test_name}")

print(f"native-degraded-truth errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
