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
const handlers=read(daemon,'internal/adapters/api/handlers_post_refactor_235_planners.go');
const presets=read(daemon,'internal/adapters/api/handlers_seventh_planners.go');
const plans=read(daemon,'internal/analysis/diagnostics/post_refactor_235_plans.go');
const prior=read(daemon,'internal/analysis/diagnostics/post_refactor_234_plans.go');
const tests=read(daemon,'internal/analysis/diagnostics/post_refactor_235_plans_test.go');
const scannerContext=read(daemon,'internal/analysis/scanner/.context');
let checks=0; const ok=(c,m)=>{checks++;if(!c)throw new Error(m)};
const rows=[
 ['scan-load-policy-plan','PlanScanLoadPolicy','scanLoadPolicy','BuildScanLoadPolicyPlan'],
 ['mobile-connection-readiness-plan','PlanMobileConnectionReadiness','mobileConnectionReadiness','BuildMobileConnectionReadinessPlan'],
 ['config-fallback-plan','PlanConfigFallback','configFallback','BuildConfigFallbackPlan'],
 ['dns-intercept-safety-plan','PlanDNSInterceptSafety','dnsInterceptSafety','BuildDNSInterceptSafetyPlan'],
 ['tor-consensus-evidence-plan','PlanTorConsensusEvidence','torConsensusEvidence','BuildTorConsensusEvidencePlan'],
 ['dnscrypt-topology-plan','PlanDNSCryptTopology','dnscryptTopology','BuildDNSCryptTopologyPlan'],
 ['evidence-receipt-topology-plan','PlanEvidenceReceiptTopology','evidenceReceiptTopology','BuildEvidenceReceiptTopologyPlan'],
 ['dns-filter-preset-plan','PlanDNSFilterPreset','dnsFilterPreset','BuildDNSFilterPresetPlan'],
 ['network-evidence-bundle-plan','PlanNetworkEvidenceBundle','networkEvidenceBundle','BuildNetworkEvidenceBundlePlan'],
];
for(const [ep,h,opt,fn] of rows){
 ok(routes.includes(`"/${ep}"`),`route ${ep}`);
 ok(handlers.includes(`func (s *Server) ${h}`),`handler ${h}`);
 ok(operations.includes(`value="${opt}"`),`option ${opt}`);
 ok(operations.includes(`/api/system/${ep}`),`ui endpoint ${ep}`);
 ok(plans.includes(`func ${fn}`),`planner ${fn}`);
}
for(const bad of ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(','os.Remove(','os.MkdirAll(','os.Chmod(']) ok(!handlers.includes(bad),`handler side effect ${bad}`);
for(const token of ['wild-scan timeout rate is informational and never independently proves congestion','invalid or failed candidates stop fallback rather than being silently bypassed','DNS-only flows must not create an otherwise-unused base transport session','unknown signature or timestamp status never counts as complete','consensus freshness is evidence, never circuit authority','resolver source unsigned, stale, or invalid','the planner reports behavior but does not mutate packets or create sessions']) ok(plans.includes(token),`semantic ${token}`);
ok(prior.includes('SensitiveFieldsOmitted'), 'API trace redaction accounting');
ok((prior+plans).includes('authorization') && (prior+plans).includes('cookie') && (prior+plans).includes('x-api-key'), 'sensitive API trace header filters');
ok(prior.includes('ProcessProxyRuleFinding') && prior.includes('shadowed') && prior.includes('conflict'), 'process rule overlap/conflict/shadowing');
for(const token of ['dns_filter_intents','config_fallback_statuses','scan_load_profiles','planner_categories']) ok(presets.includes(token),`preset ${token}`);
for(const fn of ['TestPostRefactor235ScanLoadTimeoutsDoNotProveCongestion','TestPostRefactor235ScanLoadGatewayBackoff','TestPostRefactor235MobileReadiness','TestPostRefactor235ConfigFallbackStopsOnInvalid','TestPostRefactor235DNSInterceptIsLazy','TestPostRefactor235TorConsensusFamilyAndFreshness','TestPostRefactor235DNSCryptTopologyRequiresTrustedRelay','TestPostRefactor235EvidenceReceiptDetectsMissingAndUnknown','TestPostRefactor235DNSFilterPreset','TestPostRefactor235APITraceMergesFieldsAndRedactsSensitiveHeaders','TestPostRefactor235ProcessRuleFindsConflictAndShadow','TestPostRefactor235NetworkEvidenceBundleComposesWithoutAuthority']) ok(tests.includes(`func ${fn}`),`Go test ${fn}`);
ok(!fs.existsSync(path.join(daemon,'internal/analysis/scanner/adaptive_throttle.go')),'orphan timeout throttle retired');
ok(!scannerContext.includes('`AdaptiveThrottle`'),'scanner context no stale exported throttle');
ok(scannerContext.includes('bounded diagnostics planning'),'scanner context records new ownership');
ok(pkg.scripts['test:235']==='node scripts/test-post-refactor-235.mjs','package test:235');
ok(pkg.scripts.test.includes('&& npm run test:235'),'aggregate includes 235');
console.log(`post-refactor-235 product/security second-order characterization passed: ${checks} checks`);
