#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
text = (ROOT / 'src/apps/daemon/internal/adapters/mobilebind/mobilebind.go').read_text(encoding='utf-8')
errors=[]
if not re.search(r'type\s+VPNEngine\s+struct\s*\{', text):
    errors.append('mobilebind must export a concrete VPNEngine lifecycle wrapper')
if not re.search(r'func\s+\(e\s+\*VPNEngine\)\s+Start\(tunFd\s+int32,\s*config\s+string\)\s+error', text):
    errors.append('VPNEngine.Start must use tunFd int32 so gobind exposes Java int')
if not re.search(r'func\s+\(e\s+\*VPNEngine\)\s+Stop\(\)\s+error', text):
    errors.append('VPNEngine.Stop must own lifecycle teardown')
if errors:
    for e in errors: print('ERROR:', e)
    sys.exit(1)
print('mobile_binding errors=0')
