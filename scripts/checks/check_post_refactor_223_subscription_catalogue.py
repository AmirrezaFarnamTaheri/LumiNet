#!/usr/bin/env python3
from pathlib import Path
import sys
root = Path(__file__).resolve().parents[2]
p = (root/'src/apps/daemon/internal/integrations/sub/profile_service.go').read_text()
c = (root/'src/apps/daemon/internal/integrations/sub/node_catalogue.go').read_text()
errors=[]
checks=[
 ('service owns catalogue','catalogue *NodeCatalogue' in p),
 ('constructor initializes catalogue','NewNodeCatalogue()' in p),
 ('refresh carries parsed nodes','Nodes:' in p and 'configs,' in p),
 ('validated refresh replaces catalogue','catalogue.Replace' in p),
 ('url change clears catalogue','catalogue.Clear(id)' in p),
 ('delete clears catalogue','catalogue.Clear(id)' in p),
 ('list wrapper exists','func (s *ProfileService) ListNodes(' in p),
 ('hide wrapper exists','func (s *ProfileService) SetNodesHidden(' in p),
 ('resolve wrapper exists','func (s *ProfileService) ResolveNode(' in p),
 ('catalogue is bounded','maxMaterializedNodes = 4096' in c),
]
for name, ok in checks:
    if not ok: errors.append(name)
if errors:
    print('post-refactor-223 subscription catalogue: FAIL')
    for e in errors: print(' -', e)
    sys.exit(1)
print('post-refactor-223 subscription catalogue: PASS')
