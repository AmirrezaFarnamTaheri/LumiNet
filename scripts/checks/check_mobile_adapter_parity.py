#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
errors = []

def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

mobilebind = text("src/apps/daemon/internal/adapters/mobilebind/mobilebind.go")
mobilecore = text("src/apps/daemon/internal/runtime/mobilecore/controller.go")
mobile_config = text("src/apps/daemon/internal/runtime/mobilecore/config.go")
mobile_types = text("src/apps/daemon/internal/runtime/mobilecore/types.go")
mobilehost = text("src/apps/daemon/internal/platform/mobilehost/host.go")
safety = text("src/apps/daemon/internal/runtime/safety/safety.go")
http_safety = text("src/apps/daemon/internal/adapters/api/handlers_safety_policy.go")
docs = text("docs/current-system.md")

if 'internal/runtime/proxy' in mobilebind:
    errors.append("mobilebind still imports proxy directly instead of the mobile runtime owner")

status_match = re.search(r"func StatusJSON\(\) \(string, error\) \{(?P<body>.*?)\n\}", mobilebind, re.S)
if not status_match:
    errors.append("mobile StatusJSON is missing")
elif "mobilecore.Status()" not in status_match.group("body"):
    errors.append("mobile status does not consume the mobile runtime snapshot")

status_owner = re.search(r"func Status\(\) \(MobileConfig, bool\) \{(?P<body>.*?)\n\}", mobilecore, re.S)
if not status_owner:
    errors.append("mobile runtime Status owner is missing")
else:
    body = status_owner.group("body")
    if "GetRedactedConfig()" not in body:
        errors.append("mobile runtime status does not consume the evasion redacted snapshot")
    if "ConfigFromEvasion" not in body:
        errors.append("mobile runtime status reconstructs evasion fields outside the canonical mapping")

if "Safety governor not implemented on this build" in mobilebind:
    errors.append("mobile still advertises a safety-policy stub")
if "safety.GetGovernor().ValidateScan" not in mobilebind:
    errors.append("mobile safety decisions do not use the shared SafetyGovernor")
if "safety.DefaultSettings()" not in mobilebind or "safety.DefaultSettings()" not in http_safety:
    errors.append("HTTP/mobile safety defaults do not share one owner")
if "func DefaultSettings() Settings" not in safety:
    errors.append("safety defaults owner is missing")

start_match = re.search(r"func \(c \*CoreController\) StartLoop\(configContent string, tunFd int32\) error \{(?P<body>.*?)\n\}", mobilecore, re.S)
if not start_match:
    errors.append("mobile runtime CoreController.StartLoop is missing")
else:
    body = start_match.group("body")
    if "DefaultConfig()" not in body:
        errors.append("mobile startup reconstructs evasion defaults instead of using the canonical snapshot")
    if "ConfigToEvasion(config)" not in body:
        errors.append("mobile startup reconstructs EvasionConfig field-by-field")

required_drift_fields = {
    "PrecisionSniSplits", "CovertCfg", "RandomMultiSplit", "NumFragments",
    "HostsOverride", "ShadowsocksPrefix", "AutoReconnectEnabled",
    "AutoReconnectMaxTries", "AutoReconnectDelayMs",
}
missing = sorted(name for name in required_drift_fields if name not in mobile_types)
if missing:
    errors.append("MobileConfig is missing canonical evasion fields: " + ", ".join(missing))

for required in ("func ConfigFromEvasion", "func ConfigToEvasion", "func DefaultConfig"):
    if required not in mobile_config:
        errors.append(f"mobile config owner missing {required}")

for required in ("func RegisterSocketProtector", "func ProtectSocket", "func RegisterProcessFinder", "func FindProcessConnection", "func DialContext"):
    if required not in mobilehost:
        errors.append(f"mobile host owner missing {required}")

if "generated mobile binding adapter" not in docs.lower():
    errors.append("current-system docs do not describe mobilebind as an adapter")

print(f"mobile-adapter-parity errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
