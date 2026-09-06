#!/usr/bin/env python3
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
path = ROOT / 'src/apps/daemon/internal/runtime/mobilecore/controller.go'
text = path.read_text(encoding='utf-8')

m = re.search(r'func \(c \*CoreController\) StartLoop\(configContent string, tunFd int32\) error \{(?P<body>.*?)\n\}', text, re.S)
if not m:
    print('ERROR: CoreController.StartLoop(configContent string, tunFd int32) not found')
    sys.exit(1)
body = m.group('body')

errors = []
if 'tunFd >= 0' not in body:
    errors.append('transferred TUN ownership must include fd 0; require tunFd >= 0')
newfile = body.find('os.NewFile')
running = body.find('if c.isRunning')
if newfile < 0:
    errors.append('StartLoop must wrap an incoming TUN fd with os.NewFile')
elif running < 0 or newfile > running:
    errors.append('StartLoop must take TUN fd ownership before rejecting an already-running core')
if 'mobilehost.StartTun2SocksWithDNS' not in body:
    errors.append('StartLoop must attach the real userspace mobilehost.StartTun2SocksWithDNS adapter')
if 'system.StartTun2Socks' in body:
    errors.append('StartLoop must not route mobile TUN ownership back through the broad system module')
if 'startTunDeviceRouting' in body:
    errors.append('StartLoop must not use the legacy packet-drain startTunDeviceRouting path')

if errors:
    for err in errors:
        print('ERROR:', err)
    sys.exit(1)
print('mobile_tun_ownership errors=0')
