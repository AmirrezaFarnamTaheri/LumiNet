import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const operations = readFileSync(new URL('../src/pages/Operations.tsx', import.meta.url), 'utf8');
const profiles = readFileSync(new URL('../src/pages/Profiles.tsx', import.meta.url), 'utf8');
const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
const layout = readFileSync(new URL('../src/AppLayout.tsx', import.meta.url), 'utf8');
const navigation = readFileSync(new URL('../src/navigation.ts', import.meta.url), 'utf8');

function checkOperationsRuntimeAndUpdates() {
  for (const [label, pattern] of [
    ['SSTP engine controls', /sstp/i],
    ['port preflight', /port-preflight/],
    ['signed update discovery', /update\/discover/],
    ['signed artifact staging', /update\/stage/],
    ['advanced PPP options', /PPP options/i],
  ]) {
    assert.match(operations, pattern, `Operations page must expose ${label}`);
  }
}

function checkOperationsDiagnosticsAndTrace() {
  assert.match(operations, /Export diagnostic JSON/);
  assert.match(operations, /parseTransportTrace/);
}

function checkOperationsTraceFiltering() {
  assert.match(operations, /traceCategory/);
  assert.match(operations, /traceQuery/);
}

function checkProfilesRichness() {
  for (const [label, pattern] of [
    ['source mirrors', /mirrors/i],
    ['source health', /sourceHealthByUrl/],
    ['subscription quota metadata', /subscriptionInfo/],
    ['manual refresh', /Refresh now/],
    ['auto refresh control', /auto_refresh/],
  ]) {
    assert.match(profiles, pattern, `Profiles page must expose ${label}`);
  }
}

function checkProfilesExternalLinkConfirmation() {
  assert.match(profiles, /window\.confirm/);
  assert.match(profiles, /openProviderLink/);
}

function checkNavigation() {
  assert.match(app, /path="operations"/);
  assert.match(app, /path="profiles"/);
  assert.match(layout, /navigationItems/);
  assert.match(navigation, /Operations/);
  assert.match(navigation, /Profiles/);
}

checkOperationsRuntimeAndUpdates();
checkOperationsDiagnosticsAndTrace();
checkOperationsTraceFiltering();
checkProfilesRichness();
checkProfilesExternalLinkConfirmation();
checkNavigation();

console.log('Fifth-order feature-promotion characterization: 20 checks passed');
