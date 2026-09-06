import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(here,'..');
const daemon=path.resolve(root,'../../apps/daemon');
const read=(...p)=>fs.readFileSync(path.join(...p),'utf8');
const operations=read(root,'src/pages/Operations.tsx');
const pkg=JSON.parse(read(root,'package.json'));
const routes=read(daemon,'internal/adapters/api/routes_system.go');
const handlers=read(daemon,'internal/adapters/api/handlers_post_refactor_236_planners.go');
const priorHandlers=read(daemon,'internal/adapters/api/handlers_post_refactor_235_planners.go');
const plans=read(daemon,'internal/analysis/diagnostics/post_refactor_236_plans.go');
const tests=read(daemon,'internal/analysis/diagnostics/post_refactor_236_plans_test.go');
const jq=read(daemon,'internal/analysis/diagnostics/jq_evaluator.go');
const jqTests=read(daemon,'internal/analysis/diagnostics/jq_evaluator_test.go');
let checks=0; const ok=(c,m)=>{checks++;if(!c)throw new Error(m)};
const rows=[
 ['clienthello-evidence-plan','PlanClientHelloEvidence','clientHelloEvidence','BuildClientHelloEvidencePlan'],
 ['encrypted-dns-policy-plan','PlanEncryptedDNSPolicy','encryptedDNSPolicy','BuildEncryptedDNSPolicyPlan'],
 ['tor-lab-relay-plan','PlanTorLabRelay','torLabRelay','BuildTorLabRelayPlan'],
 ['proxy-chain-safety-plan','PlanProxyChainSafety','proxyChainSafety','BuildProxyChainSafetyPlan'],
 ['transport-replay-plan','PlanTransportReplay','transportReplay','BuildTransportReplayPlan'],
 ['secret-refresh-policy-plan','PlanSecretRefreshPolicy','secretRefreshPolicy','BuildSecretRefreshPolicyPlan'],
 ['reality-admission-plan','PlanRealityAdmission','realityAdmission','BuildRealityAdmissionPlan'],
 ['service-recovery-policy-plan','PlanServiceRecoveryPolicy','serviceRecoveryPolicy','BuildServiceRecoveryPolicyPlan'],
 ['network-trust-bundle-plan','PlanNetworkTrustBundle','networkTrustBundle','BuildNetworkTrustBundlePlan'],
];
for(const [ep,h,opt,fn] of rows){
 ok(routes.includes(`"/${ep}"`),`route ${ep}`);
 ok(handlers.includes(`func (s *Server) ${h}`),`handler ${h}`);
 ok(operations.includes(`value="${opt}"`),`option ${opt}`);
 ok(operations.includes(`/api/system/${ep}`),`ui endpoint ${ep}`);
 ok(plans.includes(`func ${fn}`),`planner ${fn}`);
}
for(const bad of ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(','os.Remove(','os.MkdirAll(','os.Chmod(','syscall.']) ok(!handlers.includes(bad),`handler side effect ${bad}`);
for(const token of [
 'GREASE identifiers normalize to one placeholder before fingerprint comparison',
 'a caller-observed ECS option has precedence and is never silently overwritten',
 'rapid-bootstrap lab settings are evidence only and are never emitted as production Tor configuration',
 'strict mode never skips an unavailable selected hop',
 'replay identity is scoped by key identity plus the full 32-byte handshake salt',
 'undeclared secret lookup is denied unless allow_lookup is explicit',
 'short IDs are lowercase hexadecimal prefixes of at most eight bytes',
 'configuration is validated before a restart/reload step',
 'the bundle introduces no runtime, secret, process, DNS, Tor, proxy, TLS, firewall, or configuration authority',
]) ok(plans.includes(token),`semantic ${token}`);
for(const fn of [
 'TestPostRefactor236ClientHelloNormalizesGREASEAndDetectsQUICGaps',
 'TestPostRefactor236EncryptedDNSPreservesExistingECSAndBoundsTTL',
 'TestPostRefactor236TorLabCountsFailuresAndConsensus',
 'TestPostRefactor236ProxyChainModesAreExplicit',
 'TestPostRefactor236ReplayScopesSaltByKeyAndAge',
 'TestPostRefactor236SecretRefreshKeepsUnknownLookupClosed',
 'TestPostRefactor236RealityAdmissionRejectsMalformedShortIDs',
 'TestPostRefactor236ServiceRecoveryRequiresValidatedRollbackPath',
 'TestPostRefactor236NetworkTrustBundleDegradesConservatively',
]) ok(tests.includes(`func ${fn}`),`Go test ${fn}`);
ok(jq.includes('const maxJQResults = 4096'),'jq output bound');
ok(jq.includes('RunWithContext(ctx, input)'),'jq context-aware execution');
ok(!jq.includes('SetModuleLoader') && !jq.includes('SetEnvironLoader') && !jq.includes('SetInputIter'),'jq does not expose module/environment/input loaders');
ok(jqTests.includes('TestEvalQueryBasicAndBounded') && jqTests.includes('TestEvalQueryHonorsContext'),'jq hardening tests');
ok(priorHandlers.includes('func (s *Server) PlanNetworkEvidenceBundle(c *gin.Context)'), '235 network bundle uses canonical Gin handler path');
ok(!priorHandlers.includes('echo.Context') && !priorHandlers.includes('echo.NewHTTPError'), 'no stale Echo handler in Gin system routes');
ok(pkg.scripts['test:236']==='node scripts/test-post-refactor-236.mjs','package test:236');
ok(pkg.scripts.test.includes('&& npm run test:236'),'aggregate includes 236');
console.log(`post-refactor-236 product/security convergence characterization passed: ${checks} checks`);
