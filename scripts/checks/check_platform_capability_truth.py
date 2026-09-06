#!/usr/bin/env python3
"""Verify platform-specific controls fail closed instead of simulating success."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SYSTEM = ROOT / "src/apps/daemon/internal/platform/system"
PROCESS = ROOT / "src/apps/daemon/internal/platform/process"
API = ROOT / "src/apps/daemon/internal/adapters/api"
errors = []

def text(path: Path) -> str:
    if not path.exists():
        errors.append(f"missing required file: {path.relative_to(ROOT)}")
        return ""
    return path.read_text(encoding="utf-8")

startup = text(PROCESS / "startup_unix.go")
for stale in (SYSTEM / "startup_unix.go", SYSTEM / "startup_windows.go"):
    if stale.exists():
        errors.append(f"startup ownership leaked back into system: {stale.relative_to(ROOT)}")
if "ErrUnsupportedPlatformFeature" not in startup or "func StartupSupported() bool { return false }" not in startup:
    errors.append("non-Windows startup adapter does not fail closed / report unsupported")

ncsi = text(SYSTEM / "ncsi_unix.go")
if "func NCSISupported() bool { return false }" not in ncsi or "return nil, ncsiUnsupported()" not in ncsi:
    errors.append("non-Windows NCSI adapter still synthesizes supported state")
if re.search(r"func (?:SetNCSIConfig|ResetNCSIConfig)\b[\s\S]{0,180}return nil\b", ncsi):
    errors.append("non-Windows NCSI mutation still returns synthetic success")


windows_ncsi = text(SYSTEM / "ncsi_windows.go")
if re.search(r"_,\s*_\s*:=\s*k\.GetStringValue", windows_ncsi):
    errors.append("Windows NCSI reads still discard registry errors")
if re.search(r"_,\s*_\s*:=\s*k\.GetIntegerValue", windows_ncsi):
    errors.append("Windows NCSI integer read still discards registry errors")
if re.search(r"_\s*=\s*k\.Set(?:String|DWord)Value", windows_ncsi):
    errors.append("Windows NCSI mutation still discards registry write errors")
if re.search(r"_\s*=\s*cmd\.(?:Run|CombinedOutput)\(", windows_ncsi):
    errors.append("Windows NCSI mutation still discards NlaSvc restart errors")
if "restart NlaSvc" not in windows_ncsi or "CombinedOutput" not in windows_ncsi:
    errors.append("Windows NCSI mutation does not surface NlaSvc restart failure")
for retired in ("OverrideNcsiSettings", "GetNCSIDomains"):
    if retired in windows_ncsi or retired in ncsi:
        errors.append(f"retired zero-consumer NCSI helper returned: {retired}")

firewall = text(SYSTEM / "firewall_unix.go")
if "func DNSLeakProtectionSupported() bool { return false }" not in firewall:
    errors.append("non-Windows DNS leak protection does not report unsupported")
if "ErrUnsupportedPlatformFeature" not in firewall:
    errors.append("non-Windows leak-protection activation does not fail closed")

routes = text(SYSTEM / "tun_routes_other.go")
if "func TunRoutingSupported() bool { return false }" not in routes or "ErrUnsupportedPlatformFeature" not in routes:
    errors.append("non-Windows TUN route adapter does not fail closed")

startup_api = text(API / "handlers_system_startup.go")
if "Supported: process.StartupSupported()" not in startup_api or "writePlatformFeatureError" not in startup_api:
    errors.append("startup transport does not expose capability truth / 501 mapping")

ncsi_api = text(API / "handlers_system_ncsi.go")
if ncsi_api.count("writePlatformFeatureError") < 3:
    errors.append("NCSI transport does not map unsupported operations through capability truth")

tun_api = text(API / "handlers_system_tun.go")
for required in (
    'json:"supported"',
    'json:"dns_leak_protection_supported"',
    'json:"dns_leak_protection_active"',
    "system.TunRoutingSupported()",
    "mgr.DNSProtectionStatus()",
):
    if required not in tun_api:
        errors.append(f"TUN transport missing capability-truth marker: {required}")

for stale in (
    SYSTEM / "job_object_unix.go",
    SYSTEM / "job_object_windows.go",
):
    if stale.exists():
        errors.append(f"retired zero-consumer platform seam returned: {stale.relative_to(ROOT)}")

combined = "\n".join(p.read_text(encoding="utf-8") for p in SYSTEM.glob("*.go") if p.is_file())
for stale_symbol in ("DisableAndroidPrivateDNS", "RestoreAndroidPrivateDNS"):
    if stale_symbol in combined:
        errors.append(f"retired zero-consumer Android Private DNS helper returned: {stale_symbol}")

print(f"platform-capability-truth errors={len(errors)}")
for err in errors:
    print(f"ERROR: {err}")
raise SystemExit(1 if errors else 0)
