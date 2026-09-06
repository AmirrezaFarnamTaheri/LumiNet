#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
route = (ROOT / 'src/apps/daemon/internal/adapters/api/routes_system.go').read_text()
handler = (ROOT / 'src/apps/daemon/internal/adapters/api/handlers_seventh_planners.go').read_text()
planner = (ROOT / 'src/apps/daemon/internal/analysis/diagnostics/dns_transport_integrity.go').read_text()
errors=[]

def require(cond,msg):
    if not cond: errors.append(msg)

require('sys.POST("/dns-transport-integrity-plan", s.PlanDNSTransportIntegrity)' in route, 'DNS integrity route missing')
require('func (s *Server) PlanDNSTransportIntegrity(c *gin.Context)' in handler, 'DNS integrity handler missing')
require('var req diagnostics.DNSTransportIntegrityRequest' in handler, 'handler does not bind canonical request type')
require('diagnostics.BuildDNSTransportIntegrityPlan(req)' in handler, 'handler does not use canonical planner')
require('http.StatusBadRequest' in handler, 'handler lacks bad-request path')
require('read-only comparison; answer disagreement alone is not poisoning evidence' in planner, 'planner safety boundary drift')
if errors:
    print(f'post-refactor-223 DNS integrity: FAIL ({len(errors)} errors)')
    for e in errors: print('ERROR:',e)
    raise SystemExit(1)
print('post-refactor-223 DNS integrity: PASS')
