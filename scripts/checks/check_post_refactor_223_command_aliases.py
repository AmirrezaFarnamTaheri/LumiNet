#!/usr/bin/env python3
from pathlib import Path
import sys
p=(Path(__file__).resolve().parents[2]/'src/packages/control-ui/src/navigation.ts').read_text().lower()
expected={
 'settings':['kill switch','fail closed','auto reconnect','last working edge','system proxy'],
 'dns':['dns leak','clean ip','resolver health','poisoning'],
 'operations':['warp scanner','endpoint rank','transport truth','fec','arq'],
 'profiles':['subscription node','local socks','hidden node','provider feed'],
}
missing=[]
for group, terms in expected.items():
    for term in terms:
        if term not in p: missing.append(f'{group}:{term}')
if missing:
 print('post-refactor-223 command aliases: FAIL')
 for x in missing: print(' -',x)
 sys.exit(1)
print('post-refactor-223 command aliases: PASS')
