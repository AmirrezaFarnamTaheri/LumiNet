import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(here,'..');
const daemon=path.resolve(root,'../../apps/daemon');
const read=(...p)=>fs.readFileSync(path.join(...p),'utf8');
const operations=read(root,'src/pages/Operations.tsx');
const planners=read(root,'src/api/planners.ts');
const pkg=JSON.parse(read(root,'package.json'));
const routes=read(daemon,'internal/adapters/api/routes_system.go');
const handlers=read(daemon,'internal/adapters/api/handlers_post_refactor_231_planners.go');
const pt=read(daemon,'internal/analysis/diagnostics/pluggable_transport_plan.go');
const fallback=read(daemon,'internal/analysis/diagnostics/circumvention_fallback_plan.go');
const naive=read(daemon,'internal/analysis/diagnostics/naive_proxy_policy_plan.go');
const stego=read(daemon,'internal/analysis/diagnostics/stego_scheme_plan.go');
const tests=read(daemon,'internal/analysis/diagnostics/post_refactor_231_plans_test.go');
let checks=0; function ok(c,m){checks++;if(!c)throw new Error(m)}
for(const [ep,h] of [
 ['pluggable-transport-plan','PlanPluggableTransport'],
 ['circumvention-fallback-plan','PlanCircumventionFallback'],
 ['naive-proxy-policy-plan','PlanNaiveProxyPolicy'],
 ['stego-scheme-plan','PlanStegoScheme'],
]){ok(routes.includes(`"/${ep}"`),`route ${ep}`);ok(handlers.includes(`func (s *Server) ${h}`),`handler ${h}`)}
for(const bad of ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(','os.Remove(','os.MkdirAll(']) ok(!handlers.includes(bad),`hidden side effect ${bad}`)
for(const parser of ['parsePluggableTransportPlan','parseCircumventionFallbackPlan','parseNaiveProxyPolicyPlan','parseStegoSchemePlan']) ok(planners.includes(`export function ${parser}`),`parser ${parser}`)
for(const token of ['obfs4','meek','snowflake','webtunnel','dnstt','SingletonRequired','StateDirRequired','StateDirWritable','SafeLogging','maxPTPeers','unsafe logging']) ok(pt.includes(token),`PT token ${token}`)
ok(pt.includes('transport != "snowflake" && transport != "dnstt"'),'PT proxy support restriction');
ok(pt.includes('state == "listening" || state == "connected"'),'PT listener readiness');
ok(/StartsTransport:\s*false/.test(pt) && /PerformsNetworkIO:\s*false/.test(pt) && /WritesState:\s*false/.test(pt),'PT authority boundary');
for(const state of ['direct','snowflake','custom','obfs4','meek','webtunnel','dnstt']) ok(fallback.includes(`"${state}"`),`fallback state ${state}`)
ok(fallback.includes('MaximumTransitions: 3'),'fallback transition bound');
ok(fallback.includes('current = "direct"') || fallback.includes('current :=') || fallback.includes('case "direct"'),'fallback direct branch');
ok(fallback.includes('CustomBridgesAvailable'),'fallback custom evidence');
ok(/PerformsNetworkIO:\s*false/.test(fallback) && /StartsTransport:\s*false/.test(fallback) && /MutatesPreferences:\s*false/.test(fallback),'fallback authority boundary');
for(const token of ['naiveFirstPaddedFrames = 8','naiveFrameHeaderBytes  = 3','naiveMaxPaddingBytes   = 255','naiveMaxPayloadBytes   = 65535','maxNaiveProxyHops      = 8','maxNaiveListeners      = 16']) ok(naive.includes(token),`Naive bound ${token}`)
for(const scheme of ['http','https','socks','quic']) ok(naive.includes(`"${scheme}"`),`Naive scheme ${scheme}`)
ok(naive.includes('SOCKS proxy authentication is not admitted'),'Naive SOCKS auth guard');
ok(naive.includes('multi-proxy chains containing SOCKS are not admitted'),'Naive SOCKS chain guard');
ok(naive.includes('QUIC proxy cannot follow a TCP-based proxy'),'Naive QUIC chain guard');
ok(naive.includes('redir listener is supported only on linux'),'Naive redir platform guard');
ok(naive.includes('IPv6 resolver range is not admitted'),'Naive IPv6 resolver guard');
ok(naive.includes('FirstConnectFastOpenAllowed: padding != "variant1"'),'Naive first CONNECT fast-open suppression');
ok(/PerformsNetworkIO:\s*false/.test(naive) && /StartsProxy:\s*false/.test(naive) && /WritesResolverRules:\s*false/.test(naive),'Naive authority boundary');
for(const scheme of ['cookie-transmit','uri-transmit','json-post','pdf-post','jpeg-post','raw-post','swf-get','pdf-get','js-get','html-get','json-get','jpeg-get','raw-get']) ok(stego.includes(`"${scheme}"`),`stego scheme ${scheme}`)
ok(stego.includes('req.PayloadBytes < 300'),'stego URI small payload threshold');
ok(stego.includes('req.PayloadBytes < 700'),'stego cookie small payload threshold');
ok(stego.includes('raw.RecentFailures >= 3'),'stego failure quarantine threshold');
ok(stego.includes('raw.CapacityBytes < req.PayloadBytes'),'stego capacity admission');
ok(stego.includes('sha256.Sum256'),'stego deterministic rank');
ok(/EmbedsPayload:\s*false/.test(stego) && /LoadsCoverAssets:\s*false/.test(stego) && /PerformsNetworkIO:\s*false/.test(stego) && /MutatesSchemeState:\s*false/.test(stego),'stego authority boundary');
for(const option of ['ptLifecycle','circumventionFallback','naivePolicy','stegoScheme']) {ok(operations.includes(`value="${option}"`),`Operations option ${option}`);ok(operations.includes(`${option}:`),`Operations example ${option}`)}
for(const ep of ['/api/system/pluggable-transport-plan','/api/system/circumvention-fallback-plan','/api/system/naive-proxy-policy-plan','/api/system/stego-scheme-plan']) ok(operations.includes(ep),`Operations endpoint ${ep}`)
for(const fn of ['TestPostRefactor231PluggableTransportPlan','TestPostRefactor231CircumventionFallbackPlan','TestPostRefactor231NaiveProxyPolicyPlan','TestPostRefactor231StegoSchemePlan']) ok(tests.includes(`func ${fn}`),`Go contract test ${fn}`)
ok(pkg.scripts['test:231']==='node scripts/test-post-refactor-231.mjs','package test:231 script');
ok(pkg.scripts.test.includes('&& npm run test:231'),'aggregate includes test:231 and preserves successor tail');
if (checks !== 98) throw new Error(`unexpected post-refactor-231 characterization count: ${checks}`);
console.log(`post-refactor-231 product/security convergence characterization passed: ${checks} checks`);
