#!/usr/bin/env python3
from pathlib import Path
import sys,re
root=Path(__file__).resolve().parents[2]
c=(root/'src/packages/control-ui/src/api/contracts.ts').read_text()
p=(root/'src/packages/control-ui/src/pages/Profiles.tsx').read_text()
errors=[]
def need(n,x):
    if not x: errors.append(n)
need('node type','export interface SubscriptionNode' in c)
need('runtime type','export interface SubscriptionRuntimeStatus' in c)
need('nodes parser','parseSubscriptionNodes' in c)
need('runtime parser','parseSubscriptionRuntime' in c)
need('node API route','/nodes?include_hidden=true' in p)
need('visibility API route','/nodes/visibility' in p)
need('activate API route','/activate' in p)
need('runtime stop API route','/api/subscriptions/runtime/stop' in p)
need('manage nodes affordance','Manage nodes' in p)
need('system proxy non-authority copy','does not change the system proxy' in p)
need('hidden state surfaced','node.hidden' in p)
need('credentials absent from node contract', not re.search(r'interface SubscriptionNode[\s\S]{0,700}(uuid|password|privateKey|rawUri)', c, re.I))
if errors:
 print('post-refactor-223 subscription nodes UI: FAIL')
 for e in errors: print(' -',e)
 sys.exit(1)
print('post-refactor-223 subscription nodes UI: PASS')
