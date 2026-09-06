#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
manifest=json.loads((ROOT/'governance/topology/wave21-proxy-liveness.json').read_text())
errors=[]
for row in manifest.get('retired',[]):
    p=ROOT/row['former_live_path']
    if p.exists(): errors.append(f"retired proxy surface returned: {p.relative_to(ROOT)}")
    if not row.get('sha256') or not row.get('size'):
        errors.append(f"retirement lacks baseline provenance: {row.get('baseline_path')}")
jni=ROOT/'src/apps/daemon/internal/runtime/proxy/package_exclusions_jni.go'
if not jni.is_file(): errors.append('JNI package-exclusion entry surface was incorrectly retired')
if jni.is_file() and 'Java_com_github_shadowsocks' not in jni.read_text(errors='replace'):
    errors.append('JNI package-exclusion surface lost native export names')
print(f"proxy-liveness retired={len(manifest.get('retired',[]))} kept_native=1 errors={len(errors)}")
for e in errors: print('ERROR:',e)
raise SystemExit(1 if errors else 0)
