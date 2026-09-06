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
const handlers=read(daemon,'internal/adapters/api/handlers_post_refactor_232_planners.go');
const multipath=read(daemon,'internal/analysis/diagnostics/multipath_transport_plan.go');
const campaign=read(daemon,'internal/analysis/diagnostics/dns_resolver_campaign_plan.go');
const outline=read(daemon,'internal/analysis/diagnostics/outline_access_plan.go');
const deploy=read(daemon,'internal/networking/dnstunnel/deployment_plan.go');
const plannerTests=read(daemon,'internal/analysis/diagnostics/post_refactor_232_plans_test.go');
const deployTests=read(daemon,'internal/networking/dnstunnel/deployment_plan_test.go');
const outlineImport=read(daemon,'internal/integrations/sub/outline_import.go');
const ingest=read(daemon,'internal/integrations/sub/ingest.go');
const outlineTests=read(daemon,'internal/integrations/sub/outline_import_test.go');
let checks=0; function ok(c,m){checks++;if(!c)throw new Error(m)}
for(const [ep,h] of [
 ['multipath-transport-plan','PlanMultipathTransport'],
 ['dns-resolver-campaign-plan','PlanDNSResolverCampaign'],
 ['outline-access-plan','PlanOutlineAccess'],
 ['dns-tunnel-deployment-plan','PlanDNSTunnelDeployment'],
]){ok(routes.includes(`"/${ep}"`),`route ${ep}`);ok(handlers.includes(`func (s *Server) ${h}`),`handler ${h}`)}
for(const bad of ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(','os.Remove(','os.MkdirAll(','os.Chmod(']) ok(!handlers.includes(bad),`handler hidden side effect ${bad}`)

for(const token of ['multipathSessionIDBytes      = 8','multipathLengthPrefixBytes   = 2','multipathMaxPacketBytes      = 65535','multipathDefaultQueuePackets = 32','multipathMaxQueuePackets     = 4096','multipathMaxPaths            = 32','multipathMaxPreviewPackets   = 64']) ok(multipath.includes(token),`multipath bound ${token}`)
for(const token of ['round-robin','random','backpressure','reject-new','at least two healthy ready paths','sort.Strings(plan.EligiblePaths)','sha256.Sum256']) ok(multipath.includes(token),`multipath semantic ${token}`)
ok(/StartsTransports:\s*false/.test(multipath) && /PerformsNetworkIO:\s*false/.test(multipath) && /WritesPackets:\s*false/.test(multipath) && /DropsSilently:\s*false/.test(multipath),'multipath authority boundary');
ok(multipath.includes('silent packet loss is never an implicit planner policy'),'multipath silent-drop negative guard');

for(const token of ['maxDNSCampaignCandidates  = 10_000_000','maxDNSCampaignConcurrency = 2048','maxDNSCampaignDrain       = 5000','"slipstream"','"slipnet"','"paused"','"stopping"','"complete"','batch := concurrency / 4','batch = 4','batch = 16','scan-%x']) ok(campaign.includes(token),`DNS campaign semantic ${token}`)
for(const q of ['"A"','"AAAA"','"MX"','"TXT"','"NS"','"CNAME"']) ok(campaign.includes(q),`DNS qtype ${q}`)
ok(campaign.includes('req.QuerySize < 50 || req.QuerySize > 4096'),'SlipNet query size bound');
ok(/DownloadsClients:\s*false/.test(campaign) && /MutatesMTU:\s*false/.test(campaign) && /PerformsNetworkIO:\s*false/.test(campaign) && /StartsWorkerThread:\s*false/.test(campaign),'DNS campaign authority boundary');

for(const token of ['maxOutlineAccessCandidateBytes = 8192','FingerprintSHA256','InviteUnwrapped','RemoteFetchNeeded','ssconf://','u.Scheme = "https"','localhost','public global-unicast','EvaluateExternalCoreCompatibility']) ok(outline.includes(token),`Outline planner semantic ${token}`)
ok(/PerformsNetworkIO:\s*false/.test(outline) && /PersistsSecret:\s*false/.test(outline),'Outline planner authority boundary');
ok(outline.includes('access-key material is represented by a SHA-256 fingerprint'),'Outline credential redaction invariant');
ok(outline.includes('canonical guarded-egress'),'Outline guarded egress handoff');

for(const token of ['MTU: mtu','RedirectUDPPort: 53','listen = 5300','mtu = 1232','mode = "socks"','target = 1080','target = 22','service account','firewall ownership','RollbackSteps','private key material is never returned']) ok(deploy.includes(token),`DNSTT deployment semantic ${token}`)
ok(deploy.includes('mtu < 512 || mtu > 1400'),'DNSTT MTU bound');
ok(deploy.includes('listen < 1024 || listen > 65535'),'DNSTT unprivileged listener bound');
ok(/DownloadsBinary:\s*false/.test(deploy) && /MutatesFirewall:\s*false/.test(deploy) && /WritesSystemd:\s*false/.test(deploy) && /GeneratesKeys:\s*false/.test(deploy) && /PerformsNetworkIO:\s*false/.test(deploy),'DNSTT planner authority boundary');

for(const token of ['maxOutlineInviteBytes = 8192','unwrapOutlineStaticInvite','url.PathUnescape','ParseProxyURI','ProtocolShadowsocks']) ok(outlineImport.includes(token),`Outline import semantic ${token}`)
ok(ingest.includes('unwrapOutlineStaticInvite(content)'),'Outline invite integrated before subscription format detection');
ok(ingest.indexOf('unwrapOutlineStaticInvite(content)') < ingest.indexOf('parseLumiNetBundle'),'Outline invite parsing occurs before generic format detection');
for(const forbidden of ['http.Get(','http.Post(','net.Dial(','FetchSubscription(','ResolveReference(']) ok(!outlineImport.includes(forbidden),`Outline import remains local-only ${forbidden}`)

for(const option of ['multipathTransport','dnsResolverCampaign','outlineAccess','dnsTunnelDeployment']) {ok(operations.includes(`value="${option}"`),`Operations option ${option}`);ok(operations.includes(`${option}:`),`Operations example ${option}`)}
for(const ep of ['/api/system/multipath-transport-plan','/api/system/dns-resolver-campaign-plan','/api/system/outline-access-plan','/api/system/dns-tunnel-deployment-plan']) ok(operations.includes(ep),`Operations endpoint ${ep}`)
ok(operations.includes('Every surface is planning-only') && operations.includes('multipath') && operations.includes('DNS campaign') && operations.includes('Outline access-key') && operations.includes('DNSTT deployment'),'Operations planning-only copy covers 232 surfaces');

for(const fn of [
 'TestPostRefactor232MultipathRoundRobinAndAuthority','TestPostRefactor232MultipathRandomIsDeterministic','TestPostRefactor232MultipathRejectsUnsafeOrAmbiguousInputs',
 'TestPostRefactor232DNSCampaignLifecycleAndBatching','TestPostRefactor232DNSCampaignRejectsWrongModeBounds','TestPostRefactor232OutlineStaticDynamicAndInvite'
]) ok(plannerTests.includes(`func ${fn}`),`planner Go test ${fn}`)
for(const fn of ['TestPostRefactor232DeploymentDefaultsAndAuthority','TestPostRefactor232DeploymentAAAAAndSSH','TestPostRefactor232DeploymentRejectsUnsafeInputs']) ok(deployTests.includes(`func ${fn}`),`DNSTT Go test ${fn}`)
for(const fn of ['TestPostRefactor232OutlineInviteUnwrapsLocally','TestPostRefactor232OutlineInviteMalformedStaticFragmentFailsClosed','TestPostRefactor232OutlineDynamicURLIsNotFetchedByContentParser']) ok(outlineTests.includes(`func ${fn}`),`Outline import Go test ${fn}`)

ok(pkg.scripts['test:232']==='node scripts/test-post-refactor-232.mjs','package test:232 script');
ok(pkg.scripts.test.includes('npm run test:232'),'aggregate includes test:232 and preserves successor chain');
if (checks !== 117) throw new Error(`unexpected post-refactor-232 characterization count: ${checks}`);
console.log(`post-refactor-232 product/security convergence characterization passed: ${checks} checks`);
