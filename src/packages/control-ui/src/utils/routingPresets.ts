// SPDX-License-Identifier: MIT
//
// Routing preset catalog (roadmap item 7). Surfaces the seed presets in
// `presets/seeds/` as typed summaries so the Rules page can list them
// with rule counts and outbound distribution before a user commits one
// to the routing engine. Pure functions over the bundled JSON — no
// backend round-trip.

import iranRouting from '../presets/seeds/iran_routing.json';

export interface RoutingRule {
  type: string;
  value?: string[];
  outbound: string;
  description?: string;
  [key: string]: unknown;
}

interface RoutingSeed {
  version: string;
  description: string;
  author: string;
  lastUpdated: string;
  defaultStrategy: string;
  rules: RoutingRule[];
  dnsConfig?: Record<string, unknown>;
}

export interface RoutingPresetSummary {
  id: string;
  version: string;
  description: string;
  defaultStrategy: string;
  ruleCount: number;
  /** rule counts per outbound (direct/proxy/block/…), sorted desc. */
  outboundCounts: { outbound: string; count: number }[];
  hasDnsConfig: boolean;
}

function summarize(id: string, seed: RoutingSeed): RoutingPresetSummary {
  const counts = new Map<string, number>();
  for (const rule of seed.rules) {
    const key = rule.outbound || 'unassigned';
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const outboundCounts = [...counts.entries()]
    .map(([outbound, count]) => ({ outbound, count }))
    .sort((a, b) => b.count - a.count);
  return {
    id,
    version: seed.version,
    description: seed.description,
    defaultStrategy: seed.defaultStrategy,
    ruleCount: seed.rules.length,
    outboundCounts,
    hasDnsConfig: seed.dnsConfig !== undefined,
  };
}

const PRESET_SEEDS: Record<string, RoutingSeed> = {
  iran: iranRouting as RoutingSeed,
};

/** All bundled routing presets, ready for display. */
export function listRoutingPresets(): RoutingPresetSummary[] {
  return Object.keys(PRESET_SEEDS)
    .sort()
    .map((id) => summarize(id, PRESET_SEEDS[id]!));
}

/** One preset's summary, or undefined for an unknown id. */
export function getRoutingPreset(id: string): RoutingPresetSummary | undefined {
  const seed = PRESET_SEEDS[id];
  return seed ? summarize(id, seed) : undefined;
}

/**
 * Human-facing one-line summary for a preset card, e.g.
 * "79 rules — direct: 61, proxy: 14, block: 4".
 */
export function formatPresetLine(summary: RoutingPresetSummary): string {
  const dist = summary.outboundCounts
    .map((c) => `${c.outbound}: ${c.count}`)
    .join(', ');
  return `${summary.ruleCount} rules — ${dist}`;
}
