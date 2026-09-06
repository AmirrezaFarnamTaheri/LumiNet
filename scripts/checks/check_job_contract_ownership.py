#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
errors = []

def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

manager = text("src/apps/daemon/internal/workflows/jobs/manager.go")
intents = text("src/apps/daemon/internal/workflows/jobs/intents.go")
runners = text("src/apps/daemon/internal/workflows/jobs/runners.go") + text("src/apps/daemon/internal/workflows/jobs/runners_provision.go")
dispatcher = text("src/apps/daemon/internal/workflows/jobs/dispatcher.go")
api_files = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "src/apps/daemon/internal/adapters/api").glob("handlers_*.go") if not p.name.endswith("_test.go"))
bridge = text("src/apps/daemon/internal/native/bridge/core.go")

if "func (m *JobManager) CreateJob(intent JobIntent)" not in manager:
    errors.append("JobManager.CreateJob is not owned by the typed JobIntent contract")
if "type JobIntent interface" not in intents or "jobType() JobType" not in intents:
    errors.append("sealed JobIntent interface is missing")
for needle in ("cfg.SSHPassword = redactSecret(cfg.SSHPassword)", "cfg.SSHKey = redactSecret(cfg.SSHKey)", "cfg.CFToken = redactSecret(cfg.CFToken)"):
    if needle not in intents:
        errors.append(f"provisioning persisted-config redaction missing: {needle}")
if "job.Config" in runners:
    errors.append("job runners still decode public/persisted Job.Config")
if "json.Unmarshal" in runners:
    errors.append("job runners still reconstruct private JSON schemas")
if "m.broadcaster" in runners:
    errors.append("job runners bypass synchronized event publication")
if ".CreateJob(jobs.Job" in api_files or "json.Marshal(cfg)" in api_files:
    errors.append("API handlers still submit raw job JSON")
if "DnsResolveWithTimeout" not in bridge or "DnsResolveWithTimeout" not in runners:
    errors.append("DNS job timeout is not enforced end-to-end")
if "json.Marshal(results)" not in dispatcher or "serialize job result" not in dispatcher:
    errors.append("dispatcher result serialization is not fail-closed")

print(f"job-contract-ownership errors={len(errors)}")
for error in errors:
    print(f"ERROR: {error}")
raise SystemExit(1 if errors else 0)
